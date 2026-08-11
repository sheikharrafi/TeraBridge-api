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

# Credentials
JSTOKEN  = os.environ.get("TERABOX_JSTOKEN", "")
BDSTOKEN = os.environ.get("TERABOX_BDSTOKEN", "")
LOGID    = os.environ.get("TERABOX_LOGID", "")
COOKIE   = os.environ.get("TERABOX_COOKIE", "")

UA = "dubox;P2SP;2.2.91.249;dubox;4.2.0.1;I2404;android-android;16;JSbridge1.0.10;jointbridge;1.1.39;"
ROOT_PATH = "/cloudvids"
VIDEO_EXTS = ('.mp4', '.mkv', '.webm', '.avi', '.mov', '.flv', '.wmv', '.m4v', '.3gp', '.mpg', '.mpeg', '.ts', '.m3u8')

# Token Cache Timer for Super Fast Execution
_last_token_refresh = 0

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
        async with httpx.AsyncClient(headers=HEADERS, cookies=temp_cookies, timeout=15.0) as temp_client:
            r = await temp_client.get(f"{BASE_API}/main")
            if r.status_code != 200:
                return False, f"HTTP status {r.status_code}"
            m = re.findall(r'bdstoken["\']?\s*[:=]\s*["\']([a-f0-9]{32})["\']', r.text, re.IGNORECASE)
            if m:
                return True, "Valid"
            return False, "bdstoken not found"
    except Exception as e:
        return False, f"Request failed: {str(e)}"

async def resolve_tokens_from_cookie(cookie_str):
    temp_cookies = parse_cookies(cookie_str)
    resolved = {}
    try:
        async with httpx.AsyncClient(headers=HEADERS, cookies=temp_cookies, timeout=15.0) as temp_client:
            r = await temp_client.get(f"{BASE_API}/main")
            if r.status_code != 200:
                raise Exception(f"TeraBox returned HTTP {r.status_code}")
            m1 = re.findall(r'bdstoken["\']?\s*[:=]\s*["\']([a-f0-9]{32})["\']', r.text, re.IGNORECASE)
            if m1:
                resolved["bds_token"] = m1[0]
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
            return resolved
    except Exception as e:
        raise Exception(f"Failed to resolve tokens: {str(e)}")

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
    browser_headers = {**HEADERS, "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"}
    response = await get_session().get(f"{BASE_API}/main", headers=browser_headers, timeout=20.0)
    html = response.text
    bds_match = re.search(r'["\']bdstoken["\']?\s*[:=]\s*["\']([^"\']+)', html, re.IGNORECASE)
    if bds_match:
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
        warmup = await get_session().get(share_url, headers={**HEADERS, "Referer": f"{parsed.scheme or 'https'}://{parsed.netloc}/"}, follow_redirects=True, timeout=20.0)
        bases.insert(0, f"{warmup.url.scheme}://{warmup.url.host}")
    except httpx.HTTPError:
        pass
    seen = set()
    for base in bases:
        if not base or base in seen:
            continue
        seen.add(base)
        for shorturl in (surl, f"1{surl}" if not surl.startswith("1") else surl[1:]):
            try:
                response = await get_session().get(f"{base}/api/shorturlinfo", params={"app_id": "250528", "shorturl": shorturl, "root": "1", "web": "1", "channel": "dubox", "clienttype": "0", "jsToken": JSTOKEN}, headers={**HEADERS, "Referer": f"{base}/"}, follow_redirects=True, timeout=20.0)
                data = response.json()
                if data.get("errno") == 0:
                    randsk = urllib.parse.unquote(data.get("randsk", ""))
                    if randsk:
                        get_session().cookies.set("TSID", randsk, domain=parsed.hostname, path="/")
                    return data
            except:
                continue
    return {}

async def wait_for_transfer(task_id, bdstoken_val):
    for _ in range(30):
        response = await get_session().get(f"{BASE_API}/share/taskquery", params={"taskid": str(task_id), "app_id": "250528", "web": "1", "channel": "dubox", "clienttype": "0", "jsToken": JSTOKEN, "bdstoken": bdstoken_val}, timeout=15.0)
        result = response.json()
        status = result.get("status")
        if status in (2, "success") or (status == -1 and result.get("errno") == 0):
            return {"errno": 0}
        if status in (3, "failed") or result.get("errno", 0) not in (0,):
            return result
        await asyncio.sleep(1)
    return {"errno": -1, "errmsg": "Timed out waiting for transfer"}

async def transfer_shared_file(fs_id, share_id, uk, share_session, bdstoken_val):
    sekey = urllib.parse.unquote(share_session.get("randsk", ""))
    params = {
        "app_id": "250528", "web": "1", "channel": "dubox", "clienttype": "0", 
        "jsToken": JSTOKEN, "shareid": str(share_id), "from": str(uk), 
        "sekey": sekey, "ondup": "newcopy", "async": "2", 
        "bdstoken": bdstoken_val, "logid": _new_logid()
    }
    try:
        response = await get_session().post(
            f"{BASE_API}/share/transfer", params=params, 
            data={"fsidlist": json.dumps([fs_id]), "path": ROOT_PATH},
            headers={**HEADERS, "Origin": BASE_API, "Content-Type": "application/x-www-form-urlencoded"}, 
            timeout=20.0
        )
        last_result = response.json()
    except Exception as exc:
        return {"errno": -1, "errmsg": str(exc)}

    if last_result.get("errno") in (0, 4, 12):
        task_id = last_result.get("task_id")
        if task_id and last_result.get("errno") == 0:
            task_result = await wait_for_transfer(task_id, bdstoken_val)
            if task_result.get("errno") != 0:
                return task_result
        return last_result
    return last_result

def _create_session():
    pool_conn, pool_max = int(os.environ.get("HTTP_POOL_CONNECTIONS", 50)), int(os.environ.get("HTTP_POOL_MAXSIZE", 100))
    return httpx.AsyncClient(headers=HEADERS, cookies=COOKIES_DICT, limits=httpx.Limits(max_keepalive_connections=pool_conn, max_connections=pool_max), timeout=httpx.Timeout(20.0), http2=True)

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

_VALID_SURL = re.compile(r"^[A-Za-z0-9_-]+$")
def parse_surl(url):
    if not url: raise ValueError("Empty URL")
    surl = None
    if "surl=" in url:
        surl = url.split("surl=", 1)[1].split("&", 1)[0]
    elif "/s/" in url:
        surl = url.split("/s/", 1)[1].split("?", 1)[0].split("#", 1)[0]
    else:
        stripped = url.strip()
        if "://" not in stripped and "/" not in stripped and _VALID_SURL.match(stripped):
            surl = stripped
    if not surl: raise ValueError("No surl found")
    surl = surl.rstrip("/").split("/")[-1]
    if len(surl) > 22 and surl.startswith("1"):
        for _ in range(4):
            if not surl.startswith("1") or len(surl) <= 22: break
            surl = surl[1:]
    return surl

async def _process_single_file_metadata(item, share_id, uk, share_session, bdstoken_val):
    filename = item.get("server_filename")
    fs_id = item.get("fs_id")
    size_bytes = int(item.get("size", 0))
    
    file_res = {
        "filename": filename,
        "size_bytes": size_bytes,
        "size_mb": round(size_bytes / 1024 / 1024, 2),
        "original_fs_id": fs_id,
        "fs_id": None,
        "dlink": None,
        "thumbnails": item.get("thumbs"),
        "error": None,
        "transfer_status": "not_transferred",
        "stream_ready": False,
        "stream_m3u8": None,
        "path": item.get("path"),
        "is_directory": str(item.get("isdir")) == "1"
    }

    if file_res["is_directory"]:
        file_res["error"] = "Directory"
        return file_res

    try:
        transfer_res = await transfer_shared_file(fs_id, share_id, uk, share_session, bdstoken_val)
    except Exception as e:
        file_res["error"] = f"Transfer failed: {e}"
        file_res["transfer_status"] = "failed"
        return file_res

    if transfer_res.get("errno") == 2:
        try:
            await get_session().post(f"{BASE_API}/api/create?{qp()}&bdstoken={bdstoken_val}", data={"path": ROOT_PATH, "isdir": "1", "size": "0", "block_list": "[]", "method": "post"})
            transfer_res = await transfer_shared_file(fs_id, share_id, uk, share_session, BDSTOKEN)
        except: pass

    if transfer_res.get("errno") not in (0, 4):
        file_res["error"] = f"Transfer failed (errno {transfer_res.get('errno')})"
        file_res["transfer_status"] = "failed"
        return file_res

    file_res["transfer_status"] = "success"

    try:
        extra_list = transfer_res.get("extra", {}).get("list", [])
        if extra_list:
            file_res["fs_id"] = str(extra_list[0].get("to_fs_id", ""))
    except: pass

    return file_res

_resolve_lock = asyncio.Lock()

# Added default parameters required by index.py routing logic
async def resolve_link(link, action="d", wait_for_transcoding=False, quality=None):
    async with _resolve_lock:
        return await _resolve_link(link, action, wait_for_transcoding, quality)

async def _resolve_link(link, action="d", wait_for_transcoding=False, quality=None):
    global BDSTOKEN, JSTOKEN, _last_token_refresh
    
    if time.time() - _last_token_refresh > 3600 or not BDSTOKEN:
        try:
            await refresh_account_tokens()
            _last_token_refresh = time.time()
        except Exception as e:
            return {"errno": -1, "error": f"Token error: {e}"}

    try:
        surl = parse_surl(link)
    except ValueError as e:
        return {"errno": -3, "error": str(e)}

    list_url = f"{BASE_PUBLIC}/share/list?app_id=250528&shorturl={surl}&root=1&web=1&page=1&num=100"
    try:
        share_data = (await get_session().get(list_url)).json()
    except Exception as e:
        return {"errno": -2, "error": str(e)}

    if share_data.get("errno") != 0:
        return {"errno": share_data.get("errno"), "error": "Share link invalid or expired"}

    share_session = await resolve_share_session(surl, link)
    files_list = share_data.get("list", [])
    
    results = []
    for item in files_list:
        results.append(await _process_single_file_metadata(item, share_data.get("share_id"), share_data.get("uk"), share_session, BDSTOKEN))

    fs_ids_to_resolve = [r["fs_id"] for r in results if r.get("fs_id") and not r.get("error")]
    if fs_ids_to_resolve:
        chunk_size = 100
        fs_id_chunks = [fs_ids_to_resolve[i:i + chunk_size] for i in range(0, len(fs_ids_to_resolve), chunk_size)]
        
        dlink_map = {}
        thumb_map = {}
        for chunk in fs_id_chunks:
            encoded_fsids = urllib.parse.quote(json.dumps(chunk))
            # filemetas API hit with thumb=1 for instant thumbnails
            metas_url = f"{BASE_API}/api/filemetas?{qp()}&fsids={encoded_fsids}&dlink=1&thumb=1&bdstoken={BDSTOKEN}"
            try:
                mr = await get_session().get(metas_url, timeout=15.0)
                entries = mr.json().get("list", mr.json().get("info", []))
                for entry in entries:
                    entry_fs_id = str(entry.get("fs_id", ""))
                    if entry_fs_id:
                        if entry.get("dlink"): dlink_map[entry_fs_id] = entry.get("dlink")
                        if entry.get("thumbs"): thumb_map[entry_fs_id] = entry.get("thumbs")
            except: pass

        for r in results:
            if r.get("fs_id"):
                if r["fs_id"] in dlink_map: r["dlink"] = dlink_map[r["fs_id"]]
                if r["fs_id"] in thumb_map: r["thumbnails"] = thumb_map[r["fs_id"]]

    return {
        "errno": 0,
        "title": share_data.get("title", "Unknown"),
        "share_id": share_data.get("share_id"),
        "uk": share_data.get("uk"),
        "files": results
    }
