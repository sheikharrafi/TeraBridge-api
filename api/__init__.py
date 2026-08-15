"""Runtime hook for recursive TeraBox shared-folder resolution."""

import json
import os
import urllib.parse


def _install_recursive_share_resolver():
    import downloader

    original_resolve = downloader._resolve_link
    if getattr(original_resolve, "_recursive_folder_patch", False):
        return

    async def list_shared_files_recursive(surl, root_list, share_session, max_depth=12):
        flattened = []
        visited = set()

        async def fetch_dir(dir_path, depth):
            if depth > max_depth:
                print(f"[FolderPatch][WARN] Max share depth reached: {dir_path}", flush=True)
                return
            key = dir_path or "__ROOT__"
            if key in visited:
                return
            visited.add(key)

            if dir_path is None:
                entries = root_list
            else:
                params = {
                    "app_id": "250528", "shorturl": surl, "root": "0",
                    "page": "1", "num": "100", "dir": dir_path,
                    "order": "name", "desc": "0", "showempty": "0",
                    "web": "1", "channel": "dubox", "clienttype": "0",
                    "jsToken": downloader.JSTOKEN,
                }
                sekey = urllib.parse.unquote(share_session.get("randsk", ""))
                if sekey:
                    params["sekey"] = sekey
                try:
                    r = await downloader.get_session().get(
                        f"{downloader.BASE_PUBLIC}/share/list",
                        params=params,
                        headers={**downloader.HEADERS, "Referer": f"{downloader.BASE_PUBLIC}/"},
                        timeout=20.0,
                    )
                    data = r.json()
                except Exception as exc:
                    print(f"[FolderPatch][WARN] Nested list failed: {exc}", flush=True)
                    return
                if data.get("errno") != 0 and "sekey" in params:
                    params.pop("sekey", None)
                    try:
                        r = await downloader.get_session().get(
                            f"{downloader.BASE_PUBLIC}/share/list",
                            params=params,
                            headers={**downloader.HEADERS, "Referer": f"{downloader.BASE_PUBLIC}/"},
                            timeout=20.0,
                        )
                        data = r.json()
                    except Exception as exc:
                        print(f"[FolderPatch][WARN] Nested list retry failed: {exc}", flush=True)
                        return
                if data.get("errno") != 0:
                    print(f"[FolderPatch][WARN] Cannot list {dir_path}: errno={data.get('errno')}", flush=True)
                    return
                entries = data.get("list", [])

            for entry in entries:
                if str(entry.get("isdir")) == "1":
                    child = entry.get("path") or ""
                    if child:
                        await fetch_dir(child, depth + 1)
                else:
                    item = dict(entry)
                    item["share_path"] = item.get("path") or ""
                    item["share_depth"] = depth
                    flattened.append(item)

        await fetch_dir(None, 0)
        return flattened

    async def patched_resolve(link, action="d", wait_for_transcoding=False, quality=None):
        try:
            await downloader.refresh_account_tokens()
            surl = downloader.parse_surl(link)
            r = await downloader.get_session().get(
                f"{downloader.BASE_PUBLIC}/share/list"
                f"?app_id=250528&shorturl={surl}&root=1&order=name&desc=0"
                f"&showempty=0&web=1&page=1&num=100",
                timeout=20.0,
            )
            share_data = r.json()
        except Exception:
            return await original_resolve(link, action, wait_for_transcoding, quality)

        if share_data.get("errno") != 0:
            return {
                "errno": share_data.get("errno"),
                "error": f"Share link is invalid or expired (errno={share_data.get('errno')}).",
            }

        share_session = await downloader.resolve_share_session(surl, link)
        root_list = share_data.get("list", [])
        files_list = await list_shared_files_recursive(
            surl, root_list, share_session,
            max_depth=int(os.environ.get("TERABOX_MAX_SHARE_DEPTH", "12")),
        )

        root_files = sum(1 for x in root_list if str(x.get("isdir")) != "1")
        if len(files_list) == root_files:
            return await original_resolve(link, action, wait_for_transcoding, quality)

        title = share_data.get("title", "Untitled Shared Content")
        share_id = share_data.get("share_id")
        uk = share_data.get("uk")

        existing_files = {}
        if action != "l":
            try:
                encoded_dir = urllib.parse.quote(downloader.ROOT_PATH)
                rr = await downloader.get_session().get(
                    f"{downloader.BASE_API}/api/list?{downloader.qp()}"
                    f"&dir={encoded_dir}&order=time&desc=1&showempty=0&page=1&num=1000"
                    f"&bdstoken={downloader.BDSTOKEN}", timeout=20.0,
                )
                data = rr.json()
                if data.get("errno") == 0:
                    for entry in data.get("list", []):
                        existing_files[entry.get("server_filename")] = {
                            "fs_id": str(entry.get("fs_id", "")),
                            "path": entry.get("path", ""),
                            "size": int(entry.get("size", 0)),
                            "time": int(entry.get("server_mtime") or entry.get("ctime") or 0),
                        }
            except Exception as exc:
                print(f"[FolderPatch][WARN] Existing-file scan failed: {exc}", flush=True)

        results = []
        for item in files_list:
            results.append(await downloader._process_single_file_metadata(
                item, share_id, uk, share_session, existing_files,
                action, wait_for_transcoding, downloader.BDSTOKEN, quality
            ))

        if action != "l":
            fs_ids = [x["fs_id"] for x in results if x.get("fs_id") and not x.get("error")]
            dlink_map = {}
            for start in range(0, len(fs_ids), 100):
                chunk = fs_ids[start:start + 100]
                try:
                    encoded = urllib.parse.quote(json.dumps(chunk))
                    mr = await downloader.get_session().get(
                        f"{downloader.BASE_API}/api/filemetas?{downloader.qp()}"
                        f"&fsids={encoded}&dlink=1&thumb=0&bdstoken={downloader.BDSTOKEN}",
                        timeout=20.0,
                    )
                    data = mr.json()
                    for entry in data.get("list", data.get("info", [])):
                        fid = str(entry.get("fs_id", ""))
                        if fid and entry.get("dlink"):
                            dlink_map[fid] = entry["dlink"]
                except Exception as exc:
                    print(f"[FolderPatch][WARN] filemetas failed: {exc}", flush=True)

            for item in results:
                fid = str(item.get("fs_id", ""))
                if fid in dlink_map:
                    item["dlink"] = dlink_map[fid]
                elif action == "d" and fid and not item.get("error"):
                    item["error"] = "Failed to resolve direct download link (dlink)."

        return {"errno": 0, "title": title, "share_id": share_id, "uk": uk, "files": results}

    patched_resolve._recursive_folder_patch = True
    downloader._resolve_link = patched_resolve


_install_recursive_share_resolver()
