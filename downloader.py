import httpx
import asyncio
import json
import urllib.parse
import sys
import re
import os
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
BASE_API    = "https://www.1024terabox.com"

JSTOKEN  = os.environ.get("TERABOX_JSTOKEN", "")
BDSTOKEN = os.environ.get("TERABOX_BDSTOKEN", "")
LOGID    = os.environ.get("TERABOX_LOGID", "")
COOKIE   = os.environ.get("TERABOX_COOKIE", "")

UA = "dubox;P2SP;2.2.91.249;dubox;4.2.0.1;I2404;android-android;16;JSbridge1.0.10;jointbridge;1.1.39;"
ROOT_PATH = "/cloudvids"

def parse_cookies(cookie_str):
    cookies = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies

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
    response = await get_session().get(f"{BASE_API}/main", headers=browser_headers, timeout=15.0)
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
        warmup = await get_session().get(share_url, headers={**HEADERS, "Referer": f"{parsed.scheme or 'https'}://{parsed.netloc}/"}, follow_redirects=True, timeout=15.0)
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
            params = {"app_id": "250528", "shorturl": shorturl, "root": "1", "web": "1", "channel": "dubox", "clienttype": "0", "jsToken": JSTOKEN}
            try:
                response = await get_session().get(f"{base}/api/shorturlinfo", params=params, headers={**HEADERS, "Referer": f"{base}/"}, follow_redirects=True, timeout=15.0)
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
    for _ in range(30):
        response = await get_session().get(f"{BASE_API}/share/taskquery", params={"taskid": str(task_id), "app_id": "250528", "web": "1", "channel": "dubox", "clienttype": "0", "jsToken": JSTOKEN, "bdstoken": bdstoken_val}, timeout=10.0)
        result = response.json()
        status = result.get("status")
        if status in (2, "success") or (status == -1 and result.get("errno") == 0):
            return {"errno": 0}
        if status in (3, "failed"):
            return result
        await asyncio.sleep(1)
    return {"errno": -1, "errmsg": "Timed out waiting"}

async def transfer_shared_file(fs_id, share_id, uk, share_session, bdstoken_val):
    sekey = urllib.parse.unquote(share_session.get("randsk", ""))
    params = {
        "app_id": "250528", "web": "1", "channel": "dubox", "clienttype": "0", "jsToken": JSTOKEN,
        "shareid": str(share_id), "from": str(uk), "sekey": sekey, "ondup": "newcopy", "async": "2", "bdstoken": bdstoken_val, "logid": _new_logid(),
    }
    try:
        response = await get_session().post(
            f"{BASE_API}/share/transfer", params=params, data={"fsidlist": json.dumps([fs_id]), "path": ROOT_PATH},
            headers={**HEADERS, "Origin": BASE_API, "Content-Type": "application/x-www-form-urlencoded"}, timeout=20.0
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
    limits = httpx.Limits(max_keepalive_connections=50, max_connections=100)
    s = httpx.AsyncClient(headers=HEADERS, cookies=COOKIES_DICT, limits=limits, timeout=httpx.Timeout(20.0), http2=True, follow_redirects=True)
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

def parse_surl(url):
    if not isinstance(url, str) or not url:
        raise ValueError("Empty input")
    surl = None
    if "surl=" in url:
        surl = url.split("surl=", 1)[1].split("&", 1)[0]
    elif "/s/" in url:
        surl = url.split("/s/", 1)[1].split("?", 1)[0].split("#", 1)[0]
    else:
        stripped = url.strip()
        if "://" in stripped or "/" in stripped or "." in stripped:
            raise ValueError("No marker found")
        surl = stripped
    if not surl:
        raise ValueError("No surl found")
    surl = surl.rstrip("/").split("/")[-1]
    if len(surl) > 22 and surl.startswith("1"):
        for _ in range(4):
            if not surl.startswith("1") or len(surl) <= 22:
                break
            surl = surl[1:]
    return surl

async def _process_file_metadata(item, share_id, uk, share_session, bdstoken_val):
    filename = item.get("server_filename")
    fs_id = item.get("fs_id")
    size_bytes = int(item.get("size", 0))
    
    file_res = {
        "filename": filename,
        "size_bytes": size_bytes,
        "size_mb": round(size_bytes / 1024 / 1024, 2),
        "fs_id": None,
        "dlink": None,
        "thumbnails": None,
        "error": None,
        "is_directory": str(item.get("isdir")) == "1"
    }

    if file_res["is_directory"]:
        file_res["error"] = "File is a directory"
        return file_res

    # সরাসরি ট্রান্সফার (কোনো ১০০০ ফাইল চেকিংয়ের স্লো লজিক নেই)
    transfer_res = await transfer_shared_file(fs_id, share_id, uk, share_session, bdstoken_val)
    
    if transfer_res.get("errno") not in (0, 4, 12):
        file_res["error"] = f"Transfer failed: {transfer_res.get('errno')}"
        return file_res

    try:
        extra_list = transfer_res.get("extra", {}).get("list", [])
        if extra_list:
            file_res["fs_id"] = str(extra_list[0].get("to_fs_id", ""))
    except Exception:
        pass

    if not file_res["fs_id"]:
        file_res["error"] = "Could not resolve transferred file ID."
    return file_res

_resolve_lock = asyncio.Lock()

async def resolve_link(link, action="d", wait_for_transcoding=False, quality=None):
    async with _resolve_lock:
        return await _resolve_link(link)

async def _resolve_link(link):
    global BDSTOKEN, JSTOKEN
    
    if not BDSTOKEN or not JSTOKEN:
        try:
            await refresh_account_tokens()
        except Exception as e:
            return {"status": "error", "message": f"Session error: {e}"}

    try:
        surl = parse_surl(link)
    except Exception as e:
        return {"status": "error", "message": f"Invalid link: {e}"}
        
    try:
        list_url = f"{BASE_PUBLIC}/share/list?app_id=250528&shorturl={surl}&root=1&web=1&page=1&num=100"
        r = await get_session().get(list_url)
        share_data = r.json()
    except Exception as e:
        return {"status": "error", "message": "Failed to query share list"}

    if share_data.get("errno") != 0:
        return {"status": "error", "message": "Link expired or invalid"}

    share_session = await resolve_share_session(surl, link)
    files_list = share_data.get("list", [])
    
    results = []
    for item in files_list:
        results.append(await _process_file_metadata(item, share_data.get("share_id"), share_data.get("uk"), share_session, BDSTOKEN))

    # ফাস্ট ব্যাচ ফাইলমেটা কল (dlink এবং thumbnails সহ)
    fs_ids_to_resolve = [r["fs_id"] for r in results if r.get("fs_id") and not r.get("error")]
    if fs_ids_to_resolve:
        encoded_fsids = urllib.parse.quote(json.dumps(fs_ids_to_resolve))
        try:
            mr = await get_session().get(f"{BASE_API}/api/filemetas?{qp()}&fsids={encoded_fsids}&dlink=1&thumb=1&bdstoken={BDSTOKEN}", timeout=15.0)
            metas_res = mr.json()
            entries = metas_res.get("list", metas_res.get("info", []))
            
            dlink_map = {str(e.get("fs_id")): e.get("dlink") for e in entries if e.get("dlink")}
            thumb_map = {str(e.get("fs_id")): e.get("thumbs") for e in entries if e.get("thumbs")}
            
            for r in results:
                fs_id_str = str(r.get("fs_id"))
                if fs_id_str in dlink_map:
                    r["dlink"] = dlink_map[fs_id_str]
                if fs_id_str in thumb_map:
                    r["thumbnails"] = thumb_map[fs_id_str]
        except Exception:
            pass

    return {
        "status": "success",
        "title": share_data.get("title"),
        "share_id": share_data.get("share_id"),
        "uk": share_data.get("uk"),
        "files": results
    }

async def close_session():
    global _session
    if _session is not None and not _session.is_closed:
        await _session.aclose()
