#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import base64
import itertools
import random
import string
import threading
import time
import os
import urllib.parse
import requests
import urllib3
from Crypto.Cipher import AES as AES
from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse

try:
    from curl_cffi import requests as cffi_requests
    _HAS_CFFI = True
    print("[指纹] curl_cffi 已加载，将使用 Chrome TLS 指纹伪装", flush=True)
except ImportError:
    _HAS_CFFI = False
    cffi_requests = None
    print("[指纹] 警告：curl_cffi 未安装，回退到普通请求", flush=True)

try:
    from fake_useragent import UserAgent
    UA_SOURCES = (
        UserAgent(browsers=['Mobile Safari'], platforms='mobile'),
        UserAgent(browsers=['Chrome Mobile'], platforms='mobile', min_version=100.0),
    )
except Exception:
    UA_SOURCES = ()

AUTH_API = "https://auth.platorelay.com/api"
APP_URL = "https://auth.platorelay.com/a"
FALLBACK_VERSION = "5.4.0"
VER_TTL = 3600.0

_client_version = FALLBACK_VERSION
_client_version_at = time.time()
_ver_lock = threading.Lock()

def _env_proxy_url():
    proxy_list = (os.environ.get('PROXY_LIST') or '').strip()
    if proxy_list:
        items = [p.strip() for p in proxy_list.split(',') if p.strip()]
        if items:
            return random.choice(items)
    host = (os.environ.get('PROXY_HOST') or '').strip()
    port = (os.environ.get('PROXY_PORT') or '').strip()
    if not host or not port:
        return None
    user = (os.environ.get('PROXY_USERNAME') or '').strip()
    pwd = (os.environ.get('PROXY_PASSWORD') or '').strip()
    if user and pwd:
        return f"http://{user}:{pwd}@{host}:{port}"
    return f"http://{host}:{port}"

class _CffiResp:
    def __init__(self, r):
        self.status = r.status_code
        self.data = r.content
        self.headers = dict(r.headers)

class _CffiPool:
    def __init__(self, impersonate="chrome"):
        self.impersonate = impersonate

    def _resolve_timeout(self, timeout):
        if timeout is None:
            return 30
        if hasattr(timeout, 'read') and hasattr(timeout, 'connect'):
            return timeout.read or timeout.connect or 30
        try:
            return float(timeout)
        except Exception:
            return 30

    def request(self, method, url, body=None, headers=None, timeout=None, redirect=False, **kwargs):
        t = self._resolve_timeout(timeout)
        proxy_url = _env_proxy_url()
        proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
        r = cffi_requests.request(
            method=method.upper(),
            url=url,
            data=body,
            headers=headers or {},
            impersonate=self.impersonate,
            proxies=proxies,
            timeout=t,
            allow_redirects=bool(redirect),
        )
        return _CffiResp(r)

def _http_get(url, headers=None):
    try:
        if _HAS_CFFI:
            r = cffi_requests.get(url, headers=headers or {}, impersonate="chrome", timeout=8)
            if r.status_code != 200:
                return None
            return r.text
        r = requests.get(url, headers=headers or {}, timeout=8)
        if r.status_code != 200:
            return None
        return r.text
    except Exception:
        return None

def _version_candidates(text):
    found = []
    i = 0
    data = text
    n = len(data)
    while i < n:
        if data[i] == "'":
            j = data.find("'", i + 1)
            if j < 0:
                break
            token = data[i + 1:j]
            parts = token.split('.')
            if (len(parts) == 3
                    and all(p.isdigit() for p in parts)
                    and token not in found):
                found.append(token)
            i = j + 1
            continue
        i += 1
    return found

def _version_works(version, ua):
    letters = string.ascii_letters + string.digits
    fake = ''.join(random.choice(letters) for _ in range(64))
    built = build_meta_stream(fake, user_agent=ua)
    if built is None:
        return False
    meta, stream = built
    url = f"{AUTH_API}/session/step?ticket={urllib.parse.quote(fake)}&service=3"
    body = json.dumps({"captcha": None, "meta": meta, "stream": stream, "resolved": True}).encode()
    try:
        r = step_pool.request('PUT', url, body=body, redirect=False, headers={
            'User-Agent': ua,
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'x-client-name': 'platoboost webclient',
            'x-client-version': version,
        })
        return b'outdated client' not in r.data
    except Exception:
        return False

def _refresh_client_version():
    global _client_version, _client_version_at
    try:
        html = _http_get(APP_URL, {'User-Agent': FALLBACK_UA})
        if not html:
            return
        i = html.find('/assets/index-')
        if i < 0:
            return
        j = html.find('"', i)
        if j < 0:
            return
        script_url = 'https://auth.platorelay.com' + html[i:j]

        candidates = []
        try:
            if _HAS_CFFI:
                r = cffi_requests.get(script_url, headers={
                    'User-Agent': FALLBACK_UA, 'Range': 'bytes=0-262143'
                }, impersonate="chrome", timeout=8)
            else:
                r = requests.get(script_url, headers={
                    'User-Agent': FALLBACK_UA, 'Range': 'bytes=0-262143'
                }, timeout=8)
            if r.status_code in (200, 206):
                candidates = _version_candidates(r.text)
        except Exception:
            pass
        if not candidates:
            body = _http_get(script_url, {'User-Agent': FALLBACK_UA})
            if body:
                candidates = _version_candidates(body)
        if not candidates:
            return

        ua = FALLBACK_UA
        for cand in candidates:
            if _version_works(cand, ua):
                global_set(cand)
                return
    except Exception:
        pass

def global_set(version):
    global _client_version, _client_version_at
    if version != _client_version:
        print(f'[版本] 客户端版本更新: {_client_version} -> {version}', flush=True)
    _client_version = version
    _client_version_at = time.time()

def client_version():
    global _client_version_at
    if time.time() - _client_version_at > VER_TTL:
        if _ver_lock.acquire(blocking=False):
            try:
                if time.time() - _client_version_at > VER_TTL:
                    _refresh_client_version()
                    _client_version_at = time.time()
            finally:
                _ver_lock.release()
    return _client_version

def start_version_watcher():
    def worker():
        while True:
            try:
                _refresh_client_version()
                _client_version_at = time.time()
            except Exception:
                _client_version_at = time.time()
            time.sleep(VER_TTL)
    t = threading.Thread(target=worker, daemon=True)
    t.start()

MIN_TICKET_LEN = 33

UA_POOL = []
UA_IDX = itertools.count()
UA_SCREEN = {}

SCREENS_IPHONE = ('390x844', '393x852', '375x812', '414x896', '430x932', '428x926', '360x780')
SCREENS_IPAD = ('820x1180', '834x1194', '768x1024', '744x1133', '1024x1366')
SCREENS_ANDROID = ('360x800', '412x915', '393x873', '384x854', '360x780', '412x892', '432x960')

FALLBACK_UA = ('Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_2 like Mac OS X) '
               'AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3.1 Mobile/15E148 Safari/604.1')

def screens_for(platform, os_name):
    p = (platform or '').lower()
    o = (os_name or '').lower()
    if 'ipad' in p or 'tablet' in p:
        return SCREENS_IPAD
    if 'iphone' in p or 'ipod' in p or 'ios' in o:
        return SCREENS_IPHONE
    return SCREENS_ANDROID

def build_ua_pool(size=32):
    pool = []
    if not UA_SOURCES:
        return [FALLBACK_UA]
    per = max(1, size // len(UA_SOURCES))
    for src in UA_SOURCES:
        got = 0
        tried = 0
        while got < per and tried < per * 8:
            tried += 1
            try:
                rec = src.getRandom
            except Exception:
                break
            if not isinstance(rec, dict):
                break
            s = rec.get('useragent')
            if not s or s in UA_SCREEN:
                continue
            cands = screens_for(rec.get('platform'), rec.get('os'))
            UA_SCREEN[s] = cands[hash(s) % len(cands)]
            pool.append(s)
            got += 1
    if not pool:
        pool = [FALLBACK_UA]
        UA_SCREEN.setdefault(FALLBACK_UA, SCREENS_IPHONE[0])
    return pool

def rand_ua():
    global UA_POOL
    if not UA_POOL:
        UA_POOL = build_ua_pool()
    return UA_POOL[next(UA_IDX) % len(UA_POOL)]

def pick_screen(user_agent):
    s = UA_SCREEN.get(user_agent)
    if s:
        return s
    low = (user_agent or '').lower()
    if 'ipad' in low:
        cands = SCREENS_IPAD
    elif 'iphone' in low or 'ipod' in low:
        cands = SCREENS_IPHONE
    else:
        cands = SCREENS_ANDROID
    return cands[hash(user_agent or '') % len(cands)]

def aes_ctr_encrypt(plaintext, key_bytes, iv_bytes):
    key = bytearray(key_bytes) if isinstance(key_bytes, (bytes, bytearray)) else bytearray(key_bytes)
    iv = bytearray(iv_bytes) if isinstance(iv_bytes, (bytes, bytearray)) else bytearray(iv_bytes)
    data = plaintext.encode() if isinstance(plaintext, str) else plaintext
    out = bytearray()
    for i in range(0, len(data), 16):
        blk = AES.new(bytes(key), AES.MODE_ECB).encrypt(bytes(iv))
        out += bytes(a ^ b for a, b in zip(data[i:i + 16], blk))
        j = 15
        while True:
            iv[j] = (iv[j] + 1) & 0xFF
            if iv[j] != 0:
                break
            j -= 1
            if j < 0:
                break
    return bytes(out)

def build_meta_stream(ticket, now_ms=None, user_agent=None, screen=None):
    if len(ticket) < MIN_TICKET_LEN:
        return None

    if now_ms is None:
        now_ms = int(time.time() * 1000)
    if user_agent is None:
        user_agent = rand_ua()
    if screen is None:
        screen = pick_screen(user_agent)

    key_meta = ticket[:16]
    ctr_meta = ticket[16:32]
    key_stream = ticket[1:17]
    ctr_stream = ticket[17:33]

    meta_plain = json.dumps({
        "browserInfo": [{
            "screen": screen,
            "ua": user_agent,
            "time": now_ms
        }]
    }, separators=(',', ':'))

    stream_plain = json.dumps({
        "events": [{"event": 1, "data": {"time": now_ms}}]
    }, separators=(',', ':'))

    meta = aes_ctr_encrypt(
        meta_plain,
        [ord(c) for c in key_meta],
        [ord(c) for c in ctr_meta]
    ).hex()

    stream = aes_ctr_encrypt(
        stream_plain,
        [ord(c) for c in key_stream],
        [ord(c) for c in ctr_stream]
    ).hex()

    return meta, stream

def extract_ticket(arg):
    t = arg.strip()
    if t.startswith('http'):
        parsed = urllib.parse.urlparse(t)
        qs = urllib.parse.parse_qs(parsed.query)
        if 'd' in qs:
            return qs['d'][0]
        return t
    return t

def extract_ticket_from_arg(arg):
    t = arg.strip()
    if t.startswith('http'):
        return extract_ticket(t)
    if t.endswith('.txt') or '/' in t or '\\' in t:
        try:
            with open(t) as f:
                content = f.read().strip()
                if content:
                    return extract_ticket_from_arg(content)
        except (IOError, OSError):
            pass
    return t

def decode_callback_url(loot_url):
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(loot_url).query)
    r_param = qs.get('r', [''])[0]
    if not r_param:
        return None
    b64 = r_param.replace('-', '+').replace('_', '/')
    padding = (4 - len(b64) % 4) % 4
    try:
        dec = base64.b64decode(b64 + '=' * padding).decode('utf-8')
        if dec.startswith('http'):
            return dec
    except Exception:
        pass
    return None

def extract_ticket_from_callback(callback_url):
    if not callback_url:
        return None
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(callback_url).query)
    return qs.get('d', [None])[0]

if _HAS_CFFI:
    step_pool = _CffiPool(impersonate="chrome")
else:
    _proxy_url = _env_proxy_url()
    if _proxy_url:
        step_pool = urllib3.ProxyManager(
            _proxy_url, num_pools=8, maxsize=64, block=False, retries=False,
            timeout=urllib3.Timeout(connect=3.0, read=8.0),
        )
    else:
        step_pool = urllib3.PoolManager(
            num_pools=8, maxsize=64, block=False, retries=False,
            timeout=urllib3.Timeout(connect=3.0, read=8.0),
        )

def create_session():
    s = requests.Session()
    s.headers.update({
        'User-Agent': rand_ua(),
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/plain, */*',
    })
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=8, pool_maxsize=32, max_retries=0)
    s.mount('http://', adapter)
    s.mount('https://', adapter)
    return s

def do_step(ticket, service=3, session=None, now_ms=None):
    step_ua = rand_ua()
    built = build_meta_stream(ticket, now_ms, user_agent=step_ua)
    if built is None:
        return {"success": False,
                "error": f"ticket 长度不足（{len(ticket)} 字符，至少要 {MIN_TICKET_LEN} 个）"}
    meta, stream = built

    url = f"{AUTH_API}/session/step?ticket={urllib.parse.quote(ticket)}&service={service}"

    body = json.dumps({
        "captcha": None,
        "meta": meta,
        "stream": stream,
        "resolved": True
    }).encode()

    STEP_HTTP_RETRIES = 3
    STEP_RETRY_SLEEP = 0.5
    last_err = None
    for attempt in range(STEP_HTTP_RETRIES + 1):
        try:
            r = step_pool.request('PUT', url, body=body, redirect=False, headers={
                'User-Agent': step_ua,
                'Content-Type': 'application/json',
                'Accept': 'application/json, text/plain, */*',
                'x-client-name': 'platoboost webclient',
                'x-client-version': client_version()
            })
            if r.status != 200:
                last_err = f"http {r.status}"
                if attempt < STEP_HTTP_RETRIES:
                    time.sleep(STEP_RETRY_SLEEP)
                    continue
                return {"success": False, "error": last_err}
            try:
                return json.loads(r.content)
            except Exception:
                last_err = "non-json response"
                if attempt < STEP_HTTP_RETRIES:
                    time.sleep(STEP_RETRY_SLEEP)
                    continue
                return {"success": False, "error": last_err}
        except Exception as e:
            last_err = str(e)
            if attempt < STEP_HTTP_RETRIES:
                time.sleep(STEP_RETRY_SLEEP)
                continue
            return {"success": False, "error": last_err}
    return {"success": False, "error": last_err or "step failed"}

def get_json(path_qs, retries=3, sleep=0.25):
    last_err = None
    for attempt in range(retries + 1):
        try:
            r = step_pool.request('GET', f"{AUTH_API}/{path_qs}",
                redirect=False,
                headers={'User-Agent': rand_ua(), 'Accept': 'application/json'})
            if r.status != 200:
                last_err = f"http {r.status}"
                if attempt < retries:
                    time.sleep(sleep)
                    continue
                return {"success": False, "error": last_err, "transient": True}
            try:
                return json.loads(r.content)
            except Exception:
                last_err = "non-json response"
                if attempt < retries:
                    time.sleep(sleep)
                    continue
                return {"success": False, "error": last_err, "transient": True}
        except Exception as e:
            last_err = str(e)
            if attempt < retries:
                time.sleep(sleep)
                continue
            return {"success": False, "error": last_err, "transient": True}
    return {"success": False, "error": last_err or "get failed", "transient": True}

def get_session_status(ticket, session=None):
    return get_json(f"session/status?ticket={urllib.parse.quote(ticket)}")

def get_session_metadata(ticket, session=None):
    return get_json(f"session/metadata?ticket={urllib.parse.quote(ticket)}")

INVALID_MARKERS = ('invalid payload', 'expired', 'not found', 'invalid session',
                     'invalid ticket', 'does not exist')

def check_ticket_valid(ticket, session=None):
    try:
        meta = get_session_metadata(ticket, session=session)
    except Exception:
        return True, None
    if not isinstance(meta, dict):
        return True, None
    if meta.get('success') is True:
        return True, None
    if meta.get('transient'):
        return True, None
    if meta.get('success') is False:
        msg = str(meta.get('message') or meta.get('error') or '').lower()
        if any(m in msg for m in INVALID_MARKERS):
            return False, str(meta.get('message') or meta.get('error') or 'invalid link')
        return True, None
    return True, None

# ================= 下面是缺失的 FastAPI 接口代码 =================
app = FastAPI()

@app.on_event("startup")
def startup_event():
    start_version_watcher()

@app.get("/health")
@app.get("/healthz")
@app.get("/")
def health_check():
    return {"status": "ok"}

@app.get("/delta")
def delta(url: str = Query(...)):
    ticket = extract_ticket_from_arg(url)
    if not ticket or len(ticket) < MIN_TICKET_LEN:
        return {"key": None, "error": "invalid url (no ticket)"}

    valid, err = check_ticket_valid(ticket)
    if not valid:
        return {"key": None, "error": err or "expired link"}

    result = do_step(ticket)
    if isinstance(result, dict):
        if result.get("success") is True and result.get("key"):
            return {"key": result["key"], "error": None}
        if result.get("key"):
            return {"key": result["key"], "error": None}
        err_msg = str(result.get("error", ""))
        return {"key": None, "error": err_msg}

    return {"key": None, "error": "solve failed"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
