import httpx
import asyncio
import json
import urllib.parse
import sys
import re
import os
import zipfile
import time
import hashlib

# Load environment variables from .env file if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Set stdout encoding to UTF-8 to prevent UnicodeEncodeError on Windows
if sys.version_info >= (3, 7):
    sys.stdout.reconfigure(encoding='utf-8')

BASE_PUBLIC = "https://www.terabox.com"
BASE_API    = "https://dm.1024terabox.com"

JSTOKEN  = os.environ.get("TERABOX_JSTOKEN", "")
BDSTOKEN = os.environ.get("TERABOX_BDSTOKEN", "")
LOGID    = os.environ.get("TERABOX_LOGID", "")
COOKIE   = os.environ.get("TERABOX_COOKIE", "")

UA = "dubox;P2SP;2.2.91.249;dubox;4.2.0.1;I2404;android-android;16;JSbridge1.0.10;jointbridge;1.1.39;"
ROOT_PATH = "/cloudvids"
VIDEO_EXTS = ('.mp4', '.mkv', '.webm', '.avi', '.mov', '.flv', '.wmv', '.m4v', '.3gp', '.mpg', '.mpeg', '.ts', '.m3u8')

def parse_cookies(cookie_str):
    cookies = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies

def update_credentials(cookie=None, js_token=None, bds_token=None, logid=None):
    global COOKIE, COOKIES_DICT, JSTOKEN, BDSTOKEN, LOGID
    if cookie:
        COOKIE = cookie
        COOKIES_DICT.clear()
        COOKIES_DICT.update(parse_cookies(cookie))
        client = get_session()
        client.cookies.clear()
        for k, v in COOKIES_DICT.items():
            client.cookies.set(k, v)
    if js_token:
        JSTOKEN = js_token
    if bds_token:
        BDSTOKEN = bds_token
    if logid:
        LOGID = logid

async def validate_session_cookie(cookie_str):
    temp_cookies = parse_cookies(cookie_str)
    try:
        # Added follow_redirects=True here to fix the 302 error
        async with httpx.AsyncClient(headers=HEADERS, cookies=temp_cookies, timeout=15.0, follow_redirects=True) as temp_client:
            r = await temp_client.get(f"{BASE_API}/main")
            if r.status_code != 200:
                return False, f"HTTP status {r.status_code}"
            
            m = re.findall(r'bdstoken["\']?\s*[:=]\s*["\']([a-f0-9]{32})["\']', r.text, re.IGNORECASE)
            if m:
                return True, "Valid"
            return False, "bdstoken not found (session likely expired or invalid)"
    except Exception as e:
        return False, f"Request failed: {str(e)}"

async def resolve_tokens_from_cookie(cookie_str):
    temp_cookies = parse_cookies(cookie_str)
    resolved = {}
    try:
        # Added follow_redirects=True here to fix the 302 error
        async with httpx.AsyncClient(headers=HEADERS, cookies=temp_cookies, timeout=15.0, follow_redirects=True) as temp_client:
            r = await temp_client.get(f"{BASE_API}/main")
            if r.status_code != 200:
                raise Exception(f"TeraBox returned HTTP {r.status_code}")
            
            m1 = re.findall(r'bdstoken["\']?\s*[:=]\s*["\']([a-f0-9]{32})["\']', r.text, re.IGNORECASE)
            if m1:
                resolved["bds_token"] = m1[0]
            else:
                m2 = re.search(r'bdstoken\s*=\s*["\']([a-f0-9]{32})["\']', r.text)
                if m2:
                    resolved["bds_token"] = m2.group(1)
            
            m3 = re.findall(r'jstoken["\']?\s*[:=]\s*["\'](.*?)["\']', r.text, re.IGNORECASE)
            if m3:
                decoded_js = urllib.parse.unquote(m3[0])
                arg_match = re.search(r'fn\s*\(\s*["\']([a-f0-9]{128})["\']\s*\)', decoded_js, re.IGNORECASE)
                if arg_match:
                    resolved["js_token"] = arg_match.group(1)
            
            for cookie_name, cookie_val in r.cookies.items():
                if cookie_name.lower() == "logid":
                    resolved["logid"] = cookie_val
                    break
            
            if not resolved.get("bds_token"):
                raise Exception("bdstoken not found — cookie is likely expired or invalid")
            
            return resolved
    except Exception as e:
        raise Exception(f"Failed to resolve tokens from cookie: {str(e)}")

COOKIES_DICT = parse_cookies(COOKIE)

HEADERS = {
    "User-Agent": UA,
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.8",
    "Referer": f"{BASE_API}/main?category=all&path=%2F",
    "X-Requested-With": "XMLHttpRequest",
}

def qp():
    return f"app_id=250528&web=1&channel=dubox&clienttype=0&jsToken={JSTOKEN}&dp-logid={LOGID}"

def _new_logid():
    seed = f"{int(time.time() * 1000)}{COOKIES_DICT.get('ndus', '')[:8]}"
    return hashlib.md5(seed.encode()).hexdigest().upper()

async def refresh_account_tokens():
    global JSTOKEN, BDSTOKEN, LOGID
    browser_headers = {
        **HEADERS,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Referer": f"{BASE_API}/",
    }
    # Added follow_redirects=True to ensure the request follows the 302 redirect
    response = await get_session().get(f"{BASE_API}/main", headers=browser_headers, timeout=20.0, follow_redirects=True)
    response.raise_for_status()
    html = response.text

    bds_match = re.search(r'["\']bdstoken["\']?\s*[:=]\s*["\']([^"\']+)', html, re.IGNORECASE)
    if not bds_match:
        raise RuntimeError("TeraBox did not return bdstoken; the account cookie may be expired")
    BDSTOKEN = bds_match.group(1)

    js_match = re.search(r'jsToken\s*=\s*["\']([^"\']+)', html, re.IGNORECASE)
    if js_match:
        decoded = urllib.parse.unquote(urllib.parse.unquote(js_match.group(1)))
        token_match = re.search(r'fn\(["\']([A-Fa-f0-9]{32,})["\']\)', decoded)
        JSTOKEN = token_match.group(1) if token_match else decoded
    LOGID = _new_logid()

async def resolve_share_session(surl, link):
    share_url = link if "://" in link else f"https://{link}"
    parsed = urllib.parse.urlparse(share_url)
    bases = [f"{parsed.scheme or 'https'}://{parsed.netloc}", BASE_PUBLIC, BASE_API]
    try:
        warmup = await get_session().get(
            share_url,
            headers={**HEADERS, "Referer": f"{parsed.scheme or 'https'}://{parsed.netloc}/"},
            follow_redirects=True,
            timeout=20.0,
        )
        final_base = f"{warmup.url.scheme}://{warmup.url.host}"
        bases.insert(0, final_base)
    except httpx.HTTPError:
        pass
    seen = set()
    for base in bases:
        if not base or base in seen:
            continue
        seen.add(base)
        for shorturl in (surl, f"1{surl}" if not surl.startswith("1") else surl[1:]):
            params = {
                "app_id": "250528", "shorturl": shorturl, "root": "1",
                "web": "1", "channel": "dubox", "clienttype": "0", "jsToken": JSTOKEN,
            }
            try:
                response = await get_session().get(
                    f"{base}/api/shorturlinfo",
                    params=params,
                    headers={**HEADERS, "Referer": f"{base}/"},
                    follow_redirects=True,
                    timeout=20.0,
                )
                data = response.json()
            except (httpx.HTTPError, ValueError):
                continue
            if data.get("errno") == 0:
                randsk = urllib.parse.unquote(data.get("randsk", ""))
                if randsk:
                    for domain in (parsed.hostname, urllib.parse.urlparse(BASE_API).hostname):
                        if domain:
                            get_session().cookies.set("TSID", randsk, domain=domain, path="/")
                return data
    return {}

async def wait_for_transfer(task_id, bdstoken_val):
    for _ in range(60):
        response = await get_session().get(
            f"{BASE_API}/share/taskquery",
            params={
                "taskid": str(task_id), "app_id": "250528", "web": "1",
                "channel": "dubox", "clienttype": "0", "jsToken": JSTOKEN,
                "bdstoken": bdstoken_val,
            },
            timeout=15.0,
        )
        result = response.json()
        status = result.get("status")
        if status in (2, "success") or (status == -1 and result.get("errno") == 0):
            return {"errno": 0}
        if status in (3, "failed") or result.get("errno", 0) not in (0,):
            return result
        await asyncio.sleep(2)
    return {"errno": -1, "errmsg": "Timed out waiting for TeraBox transfer"}

async def transfer_shared_file(fs_id, share_id, uk, share_session, bdstoken_val):
    sekey = urllib.parse.unquote(share_session.get("randsk", ""))
    profiles = [
        ("12", "terabox;1.40.0.132;PC;PC-Windows;10.0.26100;WindowsTeraBox"),
        ("0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
        ("5", "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"),
    ]
    last_result = {"errno": -1, "errmsg": "No transfer response"}
    for clienttype, user_agent in profiles:
        params = {
            "app_id": "250528", "web": "1" if clienttype == "0" else "0",
            "channel": "dubox", "clienttype": clienttype, "jsToken": JSTOKEN,
            "shareid": str(share_id), "from": str(uk), "sekey": sekey,
            "ondup": "newcopy", "async": "2", "bdstoken": bdstoken_val,
            "logid": _new_logid(),
        }
        try:
            response = await get_session().post(
                f"{BASE_API}/share/transfer",
                params=params,
                data={"fsidlist": json.dumps([fs_id]), "path": ROOT_PATH},
                headers={
                    **HEADERS, "User-Agent": user_agent, "Referer": f"{BASE_API}/",
                    "Origin": BASE_API, "Content-Type": "application/x-www-form-urlencoded",
                },
                timeout=30.0,
            )
            last_result = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            last_result = {"errno": -1, "errmsg": str(exc)}

        if last_result.get("errno") in (0, 4, 12):
            task_id = last_result.get("task_id")
            if task_id and last_result.get("errno") == 0:
                task_result = await wait_for_transfer(task_id, bdstoken_val)
                if task_result.get("errno") != 0:
                    return task_result
            return last_result
        if last_result.get("errno") not in (400810, 400141, -6):
            return last_result
        await asyncio.sleep(0.75)
        await refresh_account_tokens()
        bdstoken_val = BDSTOKEN
    return last_result

def _create_session():
    pool_conn = int(os.environ.get("HTTP_POOL_CONNECTIONS", 50))
    pool_max = int(os.environ.get("HTTP_POOL_MAXSIZE", 100))
    limits = httpx.Limits(max_keepalive_connections=pool_conn, max_connections=pool_max)
    s = httpx.AsyncClient(
        headers=HEADERS,
        cookies=COOKIES_DICT,
        limits=limits,
        timeout=httpx.Timeout(30.0),
        http2=True,
        follow_redirects=True  # Added this line to fix the 302 issue globally!
    )
    return s

_session = None

def get_session():
    global _session
    if _session is None or _session.is_closed:
        _session = _create_session()
    return _session

async def close_session():
    global _session
    if _session is not None and not _session.is_closed:
        await _session.aclose()

_SURL_MIN_LEN = 8
_LEADING_ONE_MAX_STRIPS = 4
_VALID_SURL = re.compile(r"^[A-Za-z0-9_-]+$")

def parse_surl(url):
    if not isinstance(url, str) or not url:
        raise ValueError("parse_surl: empty or non-string input")
    surl = None
    if "surl=" in url:
        after = url.split("surl=", 1)[1]
        surl = after.split("&", 1)[0]
    elif "/s/" in url:
        after = url.split("/s/", 1)[1]
        surl = after.split("?", 1)[0].split("#", 1)[0]
    else:
        stripped = url.strip()
        if "://" in stripped or "/" in stripped or "." in stripped:
            raise ValueError(f"parse_surl: no surl marker found in {url!r}")
        if stripped.startswith("http"):
            raise ValueError(f"parse_surl: malformed input {url!r}")
        if _VALID_SURL.match(stripped) and len(stripped) >= _SURL_MIN_LEN:
            surl = stripped
    if not surl:
        raise ValueError(f"parse_surl: no surl found in {url!r}")
    surl = surl.rstrip("/").split("/")[-1]
    if not _VALID_SURL.match(surl):
        raise ValueError(f"parse_surl: extracted value {surl!r} contains invalid characters")
    if len(surl) > 22 and surl.startswith("1"):
        for _ in range(_LEADING_ONE_MAX_STRIPS):
            if not surl.startswith("1") or len(surl) - 1 < _SURL_MIN_LEN or len(surl) <= 22:
                break
            surl = surl[1:]
    if len(surl) < _SURL_MIN_LEN:
        raise ValueError(f"parse_surl: cleaned surl {surl!r} is shorter than the {_SURL_MIN_LEN}-char minimum")
    return surl

async def _process_single_file_metadata(item, share_id, uk, share_session, existing_files, action, wait_for_transcoding, bdstoken_val, quality=None):
    filename = item.get("server_filename")
    fs_id = item.get("fs_id")
    size_bytes = int(item.get("size", 0))
    size_mb = size_bytes / 1024 / 1024
    
    file_res = {
        "filename": filename,
        "size_bytes": size_bytes,
        "size_mb": round(size_mb, 2),
        "original_fs_id": fs_id,
        "fs_id": fs_id if action == "l" else None,
        "transfer_status": "not_transferred" if action == "l" else "skipped_existing",
        "dlink": None,
        "stream_ready": False,
        "stream_m3u8": None,
        "error": None,
        "thumbnails": None,
        "path": item.get("path"),
        "is_directory": str(item.get("isdir")) == "1"
    }

    if file_res["is_directory"]:
        file_res["error"] = "File is a directory"
        return file_res

    if action == "l":
        return file_res

    my_fs_id = ""
    my_file_path = ""
    
    if filename in existing_files and existing_files[filename]["size"] == size_bytes:
        my_fs_id = existing_files[filename]["fs_id"]
        my_file_path = existing_files[filename]["path"]
    else:
        try:
            transfer_res = await transfer_shared_file(fs_id, share_id, uk, share_session, bdstoken_val)
        except Exception as e:
            file_res["error"] = f"Transfer API request failed: {e}"
            file_res["transfer_status"] = "failed"
            return file_res

        if transfer_res.get("errno") == 2:
            create_url = f"{BASE_API}/api/create?{qp()}&bdstoken={bdstoken_val}"
            create_payload = {
                "path": ROOT_PATH,
                "isdir": "1",
                "size": "0",
                "block_list": "[]",
                "method": "post"
            }
            try:
                cr = await get_session().post(create_url, data=create_payload)
                cr_res = cr.json()
                if cr_res.get("errno") in (0, -8):
                    transfer_res = await transfer_shared_file(fs_id, share_id, uk, share_session, BDSTOKEN)
            except Exception as e:
                pass

        if transfer_res.get("errno") not in (0, 4):
            file_res["error"] = f"Transfer failed with Terabox errno {transfer_res.get('errno')}"
            file_res["transfer_status"] = "failed"
            return file_res

        file_res["transfer_status"] = "success"

        try:
            extra_list = transfer_res.get("extra", {}).get("list", [])
            if extra_list:
                my_fs_id = str(extra_list[0].get("to_fs_id", ""))
                dest_path = extra_list[0].get("to", "")
                if my_fs_id:
                    if dest_path:
                        filename = dest_path.split("/")[-1]
                        my_file_path = dest_path
        except Exception:
            pass

        if not my_fs_id:
            encoded_dir = urllib.parse.quote(ROOT_PATH)
            try:
                r_list = await get_session().get(
                    f"{BASE_API}/api/list?{qp()}&dir={encoded_dir}&order=time&desc=1&showempty=0&page=1&num=20&bdstoken={bdstoken_val}"
                )
                list_res = r_list.json()
                for entry in list_res.get("list", []):
                    entry_name = entry.get("server_filename", "")
                    if filename in entry_name or entry_name in filename:
                        my_fs_id = str(entry.get("fs_id", ""))
                        filename = entry_name
                        my_file_path = entry.get("path", "")
                        break
            except Exception:
                pass

    if not my_fs_id:
        file_res["error"] = "Could not resolve transferred file ID in account."
        return file_res

    file_res["fs_id"] = my_fs_id
    file_res["filename"] = filename
    file_res["path"] = my_file_path
    
    is_video = bool(filename and filename.lower().endswith(VIDEO_EXTS))

    if action == "s" and is_video:
        if not my_file_path:
            my_file_path = ROOT_PATH.rstrip("/") + "/" + filename
        encoded_path = urllib.parse.quote(my_file_path)
        
        if quality:
            stream_types = [quality]
        else:
            stream_types = ["M3U8_AUTO_1080", "M3U8_AUTO_720", "M3U8_AUTO_480", "M3U8_AUTO_360"]
        
        async def _try_stream(stype):
            res_val = "1080p" if "1080" in stype else ("720p" if "720" in stype else ("480p" if "480" in stype else "360p"))
            url = (
                f"{BASE_API}/api/streaming?{qp()}&path={encoded_path}&type={stype}"
                f"&bdstoken={bdstoken_val}&isplayer=1&check_blue=1&clienttype=1&resolution={res_val}"
            )
            try:
                sr = await get_session().get(url, timeout=20.0)
                if sr.status_code == 200 and "#EXTM3U" in sr.text:
                    return True, 0, sr.text
                err_code = None
                try:
                    res_json = sr.json()
                    err_code = res_json.get("errno")
                except Exception:
                    pass
                return False, err_code, sr.text[:200]
            except Exception as e:
                return False, -1, str(e)
        
        best_m3u8 = None
        all_transcoding = True
        fatal_error = None
        
        for stype in stream_types:
            ok, errno, text = await _try_stream(stype)
            if ok:
                best_m3u8 = (stype, text)
                all_transcoding = False
                break
            elif errno == 130:
                continue
            elif errno in (31066,):
                fatal_error = f"File format not supported for streaming (errno {errno})"
                all_transcoding = False
                break
            elif errno in (31341, 31023):
                fatal_error = f"File path error or not found (errno {errno})"
                all_transcoding = False
                break
            else:
                all_transcoding = False
                file_res["error"] = f"Streaming API errno {errno}: {text}"
                continue
        
        if best_m3u8:
            file_res["stream_ready"] = True
            file_res["stream_m3u8"] = best_m3u8[1]
            file_res["error"] = None
        elif fatal_error:
            file_res["error"] = fatal_error
        elif all_transcoding and wait_for_transcoding:
            max_retries = 12
            retry_delay = 10
            for attempt in range(1, max_retries + 1):
                await asyncio.sleep(retry_delay)
                for stype in stream_types:
                    ok, errno, text = await _try_stream(stype)
                    if ok:
                        file_res["stream_ready"] = True
                        file_res["stream_m3u8"] = text
                        file_res["error"] = None
                        break
                if file_res["stream_ready"]:
                    break
            if not file_res["stream_ready"]:
                file_res["error"] = "transcoding_in_progress"
        elif all_transcoding:
            file_res["error"] = "transcoding_in_progress"

    return file_res

_resolve_lock = asyncio.Lock()

async def resolve_link(link, action="d", wait_for_transcoding=False, quality=None):
    async with _resolve_lock:
        return await _resolve_link(link, action, wait_for_transcoding, quality)

async def _resolve_link(link, action="d", wait_for_transcoding=False, quality=None):
    global BDSTOKEN, JSTOKEN
    
    try:
        await refresh_account_tokens()
    except Exception as e:
        return {"errno": -1, "error": f"Failed to resolve session tokens: {e}"}

    try:
        surl = parse_surl(link)
    except ValueError as e:
        return {"errno": -3, "error": f"Invalid share link: {e}"}
        
    list_url = (
        f"{BASE_PUBLIC}/share/list"
        f"?app_id=250528&shorturl={surl}&root=1&order=name&desc=0&showempty=0&web=1&page=1&num=100"
    )
    try:
        r = await get_session().get(list_url)
        share_data = r.json()
    except Exception as e:
        return {"errno": -2, "error": f"Failed to query share list: {e}"}

    if share_data.get("errno") != 0:
        return {
            "errno": share_data.get("errno"),
            "error": f"Share link is invalid or expired (errno={share_data.get('errno')}, msg={share_data.get('errmsg', 'none')}, request_id={share_data.get('request_id', 'none')})."
        }

    share_session = await resolve_share_session(surl, link)

    title = share_data.get("title", "Untitled Shared Content")
    share_id = share_data.get("share_id")
    uk = share_data.get("uk")
    files_list = share_data.get("list", [])

    existing_files = {}

    results = []
    for item in files_list:
        results.append(await _process_single_file_metadata(
            item,
            share_id,
            uk,
            share_session,
            existing_files,
            action,
            wait_for_transcoding,
            BDSTOKEN,
            quality
        ))

    if action != "l":
        fs_ids_to_resolve = [r["fs_id"] for r in results if r.get("fs_id") and not r.get("error")]
        
        if fs_ids_to_resolve:
            chunk_size = 100
            fs_id_chunks = [fs_ids_to_resolve[i:i + chunk_size] for i in range(0, len(fs_ids_to_resolve), chunk_size)]
            
            dlink_map = {}
            for chunk in fs_id_chunks:
                fsids_str = json.dumps(chunk)
                encoded_fsids = urllib.parse.quote(fsids_str)
                
                metas_url = f"{BASE_API}/api/filemetas?{qp()}&fsids={encoded_fsids}&dlink=1&thumb=0&bdstoken={BDSTOKEN}"
                try:
                    mr = await get_session().get(metas_url, timeout=20.0)
                    metas_res = mr.json()
                    
                    entries = metas_res.get("list", metas_res.get("info", []))
                    for entry in entries:
                        entry_fs_id = str(entry.get("fs_id", ""))
                        entry_dlink = entry.get("dlink", "")
                        if entry_fs_id and entry_dlink:
                            dlink_map[entry_fs_id] = entry_dlink
                except Exception as e:
                    pass

            for r in results:
                if r.get("fs_id") and not r.get("error"):
                    my_fs_id = r["fs_id"]
                    if my_fs_id in dlink_map:
                        r["dlink"] = dlink_map[my_fs_id]
                    elif action == "d":
                        r["error"] = "Failed to resolve direct download link (dlink) from batch filemetas."

    return {
        "errno": 0,
        "title": title,
        "share_id": share_id,
        "uk": uk,
        "files": results
    }

async def download_file(dlink, filename):
    print("✅ Direct download link retrieved successfully!")
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=120.0) as dl_client:
            async with dl_client.stream(
                "GET", dlink, headers={"User-Agent": UA, "Referer": BASE_API + "/"}, cookies=COOKIES_DICT,
            ) as dr:
                content_type = dr.headers.get("Content-Type", "")
                content_length = int(dr.headers.get("Content-Length", 0))

                if dr.status_code not in (200, 206) or content_length < 1000:
                    return False

                is_zip = "zip" in content_type.lower()
                temp_filename = filename + ".zip" if is_zip else filename

                with open(temp_filename, "wb") as f:
                    downloaded = 0
                    async for chunk in dr.aiter_bytes(1024 * 1024):
                        if chunk:
                            f.write(chunk)
                if is_zip:
                    try:
                        def extract_zip():
                            with zipfile.ZipFile(temp_filename, "r") as zf:
                                zf.extractall(".")
                            os.remove(temp_filename)
                        await asyncio.to_thread(extract_zip)
                        return True
                    except Exception as e:
                        return False
                else:
                    return True
    except Exception as e:
        return False

async def main():
    pass

if __name__ == "__main__":
    async def run_cli():
        try:
            await main()
        finally:
            await close_session()

    try:
        asyncio.run(run_cli())
    except KeyboardInterrupt:
        print("\nExiting...")
