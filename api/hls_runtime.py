"""Runtime HLS patch for stable browser playback."""
import asyncio
import re
import time
import urllib.parse


def _height(q):
    try:
        return int(str(q).rstrip('p'))
    except Exception:
        return 0


def _allowed_host(host):
    host = (host or '').lower().rstrip('.')
    allowed = (
        '.1024terabox.com', '.terabox.com', '.teraboxapp.com', '.terabox.app',
        '.freeterabox.com', '.nephobox.com', '.momerybox.com', '.mirrobox.com',
        '.gibibox.com', '.tibibox.com', '.4funbox.com', '.1024tera.com',
        '.1024nephobox.com', '.terabox.fun', '.terasharefile.com',
        '.teraboxlink.com', '.teraboxshare.com', '.koofr.net', '.koofr.eu',
        '.baidu.com',
        'pcs.baidu.com', 'd.pcs.1024terabox.com',
    )
    return any(host == x[1:] or host.endswith(x) for x in allowed if x.startswith('.')) or host in {x for x in allowed if not x.startswith('.')}


def _original_id(stream_url):
    try:
        return urllib.parse.parse_qs(urllib.parse.urlparse(stream_url).query).get('fs_id', [None])[0]
    except Exception:
        return None


def install(g):
    """Install robust HLS routes after api.index.py has finished importing."""
    app = g['app']
    cache = g['cache']
    limiter = g['rate_limiter']
    auth = g['check_auth']
    verify = g['verify_signature']
    sign = g['make_signed_params']
    base_url = g['_request_base_url']
    resolve = g['resolve_link_with_retry']
    proxy = g['_proxy_client']
    downloader = __import__('downloader')

    async def get_target(request, surl, fs_id):
        share = f'https://1024terabox.com/s/{surl}'
        data = cache.get(share, 's', False)
        if data is None:
            data = await resolve(share, action='s', wait_for_transcoding=False)
        if not data or data.get('errno', 0) != 0:
            return None
        files = data.get('files', []) or []
        for f in files:
            fid = f.get('original_fs_id') or _original_id(f.get('stream_url', ''))
            if fid and fs_id and str(fid) == str(fs_id):
                return f
        if fs_id:
            for f in files:
                if str(f.get('fs_id', '')) == str(fs_id):
                    return f
        videos = [f for f in files if f.get('stream_url') or str(f.get('category', '')) == '1' or str(f.get('filename', '')).lower().endswith(downloader.VIDEO_EXTS)]
        return videos[0] if len(videos) == 1 else None

    async def probe(path, q):
        qt = {'1080p':'M3U8_AUTO_1080','720p':'M3U8_AUTO_720','480p':'M3U8_AUTO_480','360p':'M3U8_AUTO_360'}[q]
        encoded = urllib.parse.quote(path)
        url = (f'{downloader.BASE_API}/api/streaming?{downloader.qp()}&path={encoded}'
               f'&type={qt}&bdstoken={downloader.BDSTOKEN}&isplayer=1&check_blue=1&clienttype=1&resolution={q}')
        try:
            r = await downloader.get_session().get(url, timeout=15.0)
            if r.status_code == 200 and '#EXTM3U' in r.text:
                return q, r.text, str(r.url)
        except Exception as e:
            print(f'[HLS] probe {q}: {e}', flush=True)
        return q, None, None

    async def best_playlist(target, requested='auto'):
        path = target.get('path') or f"{downloader.ROOT_PATH.rstrip('/')}/{target.get('filename','')}"
        qs = ['1080p','720p','480p','360p']
        if requested in qs:
            qs = [requested] + [q for q in qs if q != requested]
        cache_key = f"hls:{_original_id(target.get('stream_url','')) or target.get('fs_id','')}:{requested}"
        cached = cache.get(path, cache_key, False)
        if isinstance(cached, dict) and cached.get('playlist'):
            return cached
        found = await asyncio.gather(*(probe(path, q) for q in qs))
        ready = [(q, text, base) for q, text, base in found if text]
        if not ready:
            return None
        ready.sort(key=lambda x: _height(x[0]), reverse=True)
        q, text, base = ready[0]

        # If the provider answers with a master playlist, follow the first media
        # playlist so the browser receives one stable media playlist.
        if '#EXT-X-STREAM-INF' in text:
            lines = text.splitlines()
            children = []
            for i, line in enumerate(lines[:-1]):
                if line.startswith('#EXT-X-STREAM-INF'):
                    child = lines[i+1].strip()
                    if child and not child.startswith('#'):
                        children.append(urllib.parse.urljoin(base, child))
            for child in children:
                try:
                    cr = await downloader.get_session().get(child, timeout=15.0)
                    if cr.status_code == 200 and '#EXTINF:' in cr.text:
                        text, base = cr.text, str(cr.url)
                        break
                except Exception:
                    pass
        result = {'quality': q, 'playlist': text, 'base': base, 'saved_at': time.time()}
        cache.put(path, cache_key, False, result)
        return result

    def seg_url(request, target):
        signature = sign(request, target, '', '', kind='segment')
        return f"{base_url(request)}/api/stream/segment.ts?url={urllib.parse.quote(target, safe='')}&{signature}"

    def rewrite(request, text, base):
        uri_re = re.compile(r'URI="([^"]+)"')
        output = []
        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                output.append('')
                continue
            def uri_replace(m):
                absolute = urllib.parse.urljoin(base, m.group(1))
                return f'URI="{seg_url(request, absolute)}"' if urllib.parse.urlparse(absolute).scheme in ('http','https') else m.group(0)
            if line.startswith('#'):
                output.append(uri_re.sub(uri_replace, line))
            else:
                absolute = urllib.parse.urljoin(base, line)
                output.append(seg_url(request, absolute) if urllib.parse.urlparse(absolute).scheme in ('http','https') else line)
        return '\n'.join(output) + '\n'

    async def manifest(request):
        surl = request.query_params.get('surl','')
        fs_id = request.query_params.get('fs_id','')
        sig = request.query_params.get('sig','')
        exp = request.query_params.get('exp','')
        if not ((surl and fs_id and sig and verify(surl, fs_id, 'manifest', sig, exp)) or await auth(request)):
            return g['JSONResponse']({'status':'error','message':'Unauthorized: Invalid signature or authentication.'}, status_code=401)
        ip = g['_client_ip'](request)
        if not limiter.is_allowed(ip):
            return g['JSONResponse']({'status':'error','message':'Rate limit exceeded. Try again shortly.'}, status_code=429)
        target = await get_target(request, surl, fs_id)
        if not target:
            return g['JSONResponse']({'status':'error','message':'Video metadata is not available. Resolve the link again.'}, status_code=404)
        requested = (request.query_params.get('quality') or 'auto').lower()
        result = await best_playlist(target, requested)
        if not result:
            return g['JSONResponse']({'status':'error','message':'No playable HLS quality is currently available.'}, status_code=404)
        body = rewrite(request, result['playlist'], result['base'])
        return g['Response'](content=body, media_type='application/vnd.apple.mpegurl', headers={
            'Cache-Control':'no-store',
            'Access-Control-Allow-Origin':'*',
            'Access-Control-Expose-Headers':'Content-Type,Content-Length',
            'X-TeraBridge-Quality':result['quality'],
            'X-TeraBridge-Mode':'single-variant',
        })

    async def segment(request):
        target = request.query_params.get('url','')
        sig = request.query_params.get('sig','')
        exp = request.query_params.get('exp','')
        if not target:
            return g['Response'](content='Missing segment URL', status_code=400)
        if not ((sig and verify(target, '', '', sig, exp)) or await auth(request)):
            return g['Response'](content='Unauthorized: Invalid signature or API key.', status_code=401)
        parsed = urllib.parse.urlparse(target)
        if parsed.scheme not in ('http','https') or not _allowed_host(parsed.hostname):
            return g['Response'](content='Forbidden: Invalid stream host destination.', status_code=403)
        headers = {'User-Agent':downloader.UA,'Referer':'https://dm.1024terabox.com/'}
        for h in ('Range','If-Range','If-Modified-Since'):
            v = request.headers.get(h)
            if v: headers[h] = v
        try:
            ctx = proxy.stream('GET', target, headers=headers, cookies=downloader.COOKIES_DICT, timeout=60.0)
            r = await ctx.__aenter__()
        except Exception as e:
            return g['Response'](content=f'Segment upstream connection failed: {e}', status_code=502)
        if r.status_code >= 400:
            try:
                body = (await r.aread())[:500]
            finally:
                await ctx.__aexit__(None,None,None)
            return g['Response'](content=body, status_code=r.status_code, media_type=r.headers.get('content-type'))
        headers_out = {
            'Access-Control-Allow-Origin':'*',
            'Access-Control-Allow-Headers':'*',
            'Access-Control-Allow-Methods':'GET, OPTIONS',
            'Access-Control-Expose-Headers':'Content-Length,Content-Range,Accept-Ranges,Content-Type,ETag,Last-Modified',
            'Cache-Control':'public, max-age=30',
            'X-TeraBridge-Mode':'proxy',
        }
        for h in ('Content-Length','Content-Type','Content-Range','Accept-Ranges','ETag','Last-Modified'):
            if r.headers.get(h): headers_out[h] = r.headers[h]
        async def iterator():
            try:
                async for chunk in r.aiter_bytes(chunk_size=256*1024):
                    if chunk: yield chunk
            finally:
                await ctx.__aexit__(None,None,None)
        return g['StreamingResponse'](iterator(), status_code=r.status_code, headers=headers_out)

    paths = {'/api/stream/manifest','/api/stream/playlist.m3u8','/api/stream/segment','/api/stream/segment.ts'}
    app.router.routes = [r for r in app.router.routes if getattr(r,'path',None) not in paths]
    app.add_api_route('/api/stream/manifest', manifest, methods=['GET','OPTIONS'])
    app.add_api_route('/api/stream/playlist.m3u8', manifest, methods=['GET','OPTIONS'])
    app.add_api_route('/api/stream/segment', segment, methods=['GET','OPTIONS'])
    app.add_api_route('/api/stream/segment.ts', segment, methods=['GET','OPTIONS'])
    print('[HLS] Installed single-variant media playlist + robust URI rewrite + range proxy.', flush=True)
