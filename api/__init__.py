"""Runtime hook for robust recursive TeraBox shared-folder resolution.

This package is imported before ``api.index``.  The hook keeps the original
resolver for normal shares and only takes over when a share contains nested
folders.  It also fixes the two main performance/correctness problems in the
old patch: one-page folder listing and serial processing of every child file.
"""

import asyncio
import json
import os
import time
import urllib.parse


def _install_recursive_share_resolver():
    import downloader

    original_resolve = downloader._resolve_link
    if getattr(original_resolve, "_recursive_folder_patch", False):
        return

    # Refreshing /main for every request was a significant fixed latency cost.
    # Refresh immediately when credentials change, otherwise reuse the session
    # tokens for a short interval.  A failure never poisons the cache window.
    refresh_lock = asyncio.Lock()
    refresh_state = {"at": 0.0, "fingerprint": None}
    refresh_ttl = max(0, float(os.environ.get("TERABOX_TOKEN_REFRESH_TTL", "20")))

    async def refresh_tokens_if_needed():
        fingerprint = (
            getattr(downloader, "COOKIE", ""),
            getattr(downloader, "JSTOKEN", ""),
            getattr(downloader, "BDSTOKEN", ""),
        )
        now = time.monotonic()
        if refresh_ttl > 0 and refresh_state["fingerprint"] == fingerprint and now - refresh_state["at"] < refresh_ttl:
            return
        async with refresh_lock:
            fingerprint = (
                getattr(downloader, "COOKIE", ""),
                getattr(downloader, "JSTOKEN", ""),
                getattr(downloader, "BDSTOKEN", ""),
            )
            now = time.monotonic()
            if refresh_ttl > 0 and refresh_state["fingerprint"] == fingerprint and now - refresh_state["at"] < refresh_ttl:
                return
            await downloader.refresh_account_tokens()
            refresh_state["at"] = time.monotonic()
            refresh_state["fingerprint"] = (
                getattr(downloader, "COOKIE", ""),
                getattr(downloader, "JSTOKEN", ""),
                getattr(downloader, "BDSTOKEN", ""),
            )

    async def _get_share_dir(surl, share_session, dir_path, page=1, num=100):
        params = {
            "app_id": "250528",
            "shorturl": surl,
            "root": "0",
            "page": str(page),
            "num": str(num),
            "dir": dir_path,
            "order": "name",
            "desc": "0",
            "showempty": "0",
            "web": "1",
            "channel": "dubox",
            "clienttype": "0",
            "jsToken": downloader.JSTOKEN,
        }
        sekey = urllib.parse.unquote(share_session.get("randsk", ""))
        if sekey:
            params["sekey"] = sekey

        async def request_once(with_sekey=True):
            local_params = dict(params)
            if not with_sekey:
                local_params.pop("sekey", None)
            response = await downloader.get_session().get(
                f"{downloader.BASE_PUBLIC}/share/list",
                params=local_params,
                headers={**downloader.HEADERS, "Referer": f"{downloader.BASE_PUBLIC}/"},
                timeout=20.0,
            )
            return response.json()

        data = await request_once(with_sekey=True)
        if data.get("errno") != 0 and "sekey" in params:
            data = await request_once(with_sekey=False)
        return data

    async def list_shared_files_recursive(surl, root_list, share_session, max_depth=12):
        flattened = []
        visited = set()
        semaphore = asyncio.Semaphore(max(1, int(os.environ.get("TERABOX_FOLDER_CONCURRENCY", "8"))))
        page_size = max(20, min(100, int(os.environ.get("TERABOX_FOLDER_PAGE_SIZE", "100"))))

        async def fetch_dir(dir_path, depth, entries=None):
            if depth > max_depth:
                print(f"[FolderPatch][WARN] Max share depth reached: {dir_path}", flush=True)
                return

            key = dir_path or "__ROOT__"
            if key in visited:
                return
            visited.add(key)

            if entries is None:
                all_entries = []
                page = 1
                while True:
                    try:
                        async with semaphore:
                            data = await _get_share_dir(surl, share_session, dir_path or "", page, page_size)
                    except Exception as exc:
                        print(f"[FolderPatch][WARN] Nested list failed ({dir_path}, page={page}): {exc}", flush=True)
                        break
                    if data.get("errno") != 0:
                        print(f"[FolderPatch][WARN] Cannot list {dir_path}: errno={data.get('errno')}", flush=True)
                        break
                    batch = data.get("list", []) or []
                    all_entries.extend(batch)
                    if len(batch) < page_size:
                        break
                    page += 1
                    if page > 1000:
                        print(f"[FolderPatch][WARN] Pagination safety limit reached: {dir_path}", flush=True)
                        break
                entries = all_entries

            child_dirs = []
            for entry in entries:
                if str(entry.get("isdir")) == "1":
                    child = entry.get("path") or ""
                    if child:
                        child_dirs.append((child, depth + 1))
                else:
                    item = dict(entry)
                    item["share_path"] = item.get("path") or ""
                    item["share_depth"] = depth
                    flattened.append(item)

            if child_dirs:
                await asyncio.gather(*(fetch_dir(child, child_depth) for child, child_depth in child_dirs))

        # The root response is already available; paginate every nested dir.
        await fetch_dir(None, 0, root_list)
        return flattened

    async def patched_resolve(link, action="d", wait_for_transcoding=False, quality=None):
        started = time.perf_counter()
        try:
            await refresh_tokens_if_needed()
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

        root_list = share_data.get("list", []) or []
        has_directories = any(str(x.get("isdir")) == "1" for x in root_list)
        if not has_directories:
            return await original_resolve(link, action, wait_for_transcoding, quality)

        share_session = await downloader.resolve_share_session(surl, link)
        files_list = await list_shared_files_recursive(
            surl,
            root_list,
            share_session,
            max_depth=int(os.environ.get("TERABOX_MAX_SHARE_DEPTH", "12")),
        )

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
                    f"&bdstoken={downloader.BDSTOKEN}",
                    timeout=20.0,
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

        file_concurrency = max(1, int(os.environ.get("TERABOX_FILE_CONCURRENCY", "8")))
        file_semaphore = asyncio.Semaphore(file_concurrency)

        async def process_file(item):
            async with file_semaphore:
                return await downloader._process_single_file_metadata(
                    item,
                    share_id,
                    uk,
                    share_session,
                    existing_files,
                    action,
                    wait_for_transcoding,
                    downloader.BDSTOKEN,
                    quality,
                )

        results = await asyncio.gather(*(process_file(item) for item in files_list)) if files_list else []

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

        elapsed_ms = (time.perf_counter() - started) * 1000
        print(
            f"[FolderPatch] Resolved nested share: files={len(results)} action={action} "
            f"elapsed_ms={elapsed_ms:.0f}",
            flush=True,
        )
        return {"errno": 0, "title": title, "share_id": share_id, "uk": uk, "files": results}

    patched_resolve._recursive_folder_patch = True
    downloader._resolve_link = patched_resolve


_install_recursive_share_resolver()
