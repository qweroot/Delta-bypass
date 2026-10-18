import os
import time
import json
import random
import re
import socket
import ssl
import struct
import base64
import urllib.parse
from fastapi import FastAPI, Query
from pydantic import BaseModel
from typing import List

HOST = "bypass.lat"
PORT = 443
BASE_PATH = "/BETA-BYPASS"
H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_RST = 0x3
FRAME_SETTINGS = 0x4
FRAME_PING = 0x6
FRAME_GOAWAY = 0x7
FRAME_WINDOW = 0x8
FRAME_CONT = 0x9
FLAG_END_STREAM = 0x1
FLAG_ACK = 0x1
FLAG_END_HEADERS = 0x4

HUFF = [(0x1ff8,13),(0x7fffd8,23),(0xfffffe2,28),(0xfffffe3,28),(0xfffffe4,28),(0xfffffe5,28),(0xfffffe6,28),(0xfffffe7,28),(0xfffffe8,28),(0xffffea,24),(0x3ffffffc,30),(0xfffffe9,28),(0xfffffea,28),(0x3ffffffd,30),(0xfffffeb,28),(0xfffffec,28),(0xfffffed,28),(0xfffffee,28),(0xfffffef,28),(0xffffff0,28),(0xffffff1,28),(0xffffff2,28),(0x3ffffffe,30),(0xffffff3,28),(0xffffff4,28),(0xffffff5,28),(0xffffff6,28),(0xffffff7,28),(0xffffff8,28),(0xffffff9,28),(0xffffffa,28),(0xffffffb,28),(0x14,6),(0x3f8,10),(0x3f9,10),(0xffa,12),(0x1ff9,13),(0x15,6),(0xf8,8),(0x7fa,11),(0x3fa,10),(0x3fb,10),(0xf9,8),(0x7fb,11),(0xfa,8),(0x16,6),(0x17,6),(0x18,6),(0x0,5),(0x1,5),(0x2,5),(0x19,6),(0x1a,6),(0x1b,6),(0x1c,6),(0x1d,6),(0x1e,6),(0x1f,6),(0x5c,7),(0xfb,8),(0x7ffc,15),(0x20,6),(0xffb,12),(0x3fc,10),(0x1ffa,13),(0x21,6),(0x5d,7),(0x5e,7),(0x5f,7),(0x60,7),(0x61,7),(0x62,7),(0x63,7),(0x64,7),(0x65,7),(0x66,7),(0x67,7),(0x68,7),(0x69,7),(0x6a,7),(0x6b,7),(0x6c,7),(0x6d,7),(0x6e,7),(0x6f,7),(0x70,7),(0x71,7),(0x72,7),(0xfc,8),(0x73,7),(0xfd,8),(0x1ffb,13),(0x7fff0,19),(0x1ffc,13),(0x3ffc,14),(0x22,6),(0x7ffd,15),(0x3,5),(0x23,6),(0x4,5),(0x24,6),(0x5,5),(0x25,6),(0x26,6),(0x27,6),(0x6,5),(0x74,7),(0x75,7),(0x28,6),(0x29,6),(0x2a,6),(0x7,5),(0x2b,6),(0x76,7),(0x2c,6),(0x8,5),(0x9,5),(0x2d,6),(0x77,7),(0x78,7),(0x79,7),(0x7a,7),(0x7b,7),(0x7ffe,15),(0x7fc,11),(0x3ffd,14),(0x1ffd,13),(0xffffffc,28),(0xfffe6,20),(0x3fffd2,22),(0xfffe7,20),(0xfffe8,20),(0x3fffd3,22),(0x3fffd4,22),(0x3fffd5,22),(0x7fffd9,23),(0x3fffd6,22),(0x7fffda,23),(0x7fffdb,23),(0x7fffdc,23),(0x7fffdd,23),(0x7fffde,23),(0xffffeb,24),(0x7fffdf,23),(0xffffec,24),(0xffffed,24),(0x3fffd7,22),(0x7fffe0,23),(0xffffee,24),(0x7fffe1,23),(0x7fffe2,23),(0x7fffe3,23),(0x7fffe4,23),(0x1fffdc,21),(0x3fffd8,22),(0x7fffe5,23),(0x3fffd9,22),(0x7fffe6,23),(0x7fffe7,23),(0xffffef,24),(0x3fffda,22),(0x1fffdd,21),(0xfffe9,20),(0x3fffdb,22),(0x3fffdc,22),(0x7fffe8,23),(0x7fffe9,23),(0x1fffde,21),(0x7fffea,23),(0x3fffdd,22),(0x3fffde,22),(0xfffff0,24),(0x1fffdf,21),(0x3fffdf,22),(0x7fffeb,23),(0x7fffec,23),(0x1fffe0,21),(0x1fffe1,21),(0x3fffe0,22),(0x1fffe2,21),(0x7fffed,23),(0x3fffe1,22),(0x7fffee,23),(0x7fffef,23),(0xfffea,20),(0x3fffe2,22),(0x3fffe3,22),(0x3fffe4,22),(0x7ffff0,23),(0x3fffe5,22),(0x3fffe6,22),(0x7ffff1,23),(0x3ffffe0,26),(0x3ffffe1,26),(0xfffeb,20),(0x7fff1,19),(0x3fffe7,22),(0x7ffff2,23),(0x3fffe8,22),(0x1ffffec,25),(0x3ffffe2,26),(0x3ffffe3,26),(0x3ffffe4,26),(0x7ffffde,27),(0x7ffffdf,27),(0x3ffffe5,26),(0xfffff1,24),(0x1ffffed,25),(0x7fff2,19),(0x1fffe3,21),(0x3ffffe6,26),(0x7ffffe0,27),(0x7ffffe1,27),(0x3ffffe7,26),(0x7ffffe2,27),(0xfffff2,24),(0x1fffe4,21),(0x1fffe5,21),(0x3ffffe8,26),(0x3ffffe9,26),(0xffffffd,28),(0x7ffffe3,27),(0x7ffffe4,27),(0x7ffffe5,27),(0xfffec,20),(0xfffff3,24),(0xfffed,20),(0x1fffe6,21),(0x3fffe9,22),(0x1fffe7,21),(0x1fffe8,21),(0x7ffff3,23),(0x3fffea,22),(0x3fffeb,22),(0x1ffffee,25),(0x1ffffef,25),(0xfffff4,24),(0xfffff5,24),(0x3ffffea,26),(0x7ffff4,23),(0x3ffffeb,26),(0x7ffffe6,27),(0x3ffffec,26),(0x3ffffed,26),(0x7ffffe7,27),(0x7ffffe8,27),(0x7ffffe9,27),(0x7ffffea,27),(0x7ffffeb,27),(0xffffffe,28),(0x7ffffec,27),(0x7ffffed,27),(0x7ffffee,27),(0x7ffffef,27),(0x7fffff0,27),(0x3ffffee,26),(0x3fffffff,30)]
HUFF_MAP = {}
for _i, (_c, _l) in enumerate(HUFF):
    HUFF_MAP[(_c, _l)] = _i

STATIC = [(":authority",""),(":method","GET"),(":method","POST"),(":path","/"),(":path","/index.html"),(":scheme","http"),(":scheme","https"),(":status","200"),(":status","204"),(":status","206"),(":status","304"),(":status","400"),(":status","404"),(":status","500"),("accept-charset",""),("accept-encoding","gzip, deflate"),("accept-language",""),("accept-ranges",""),("accept",""),("access-control-allow-origin",""),("age",""),("allow",""),("authorization",""),("cache-control",""),("content-disposition",""),("content-encoding",""),("content-language",""),("content-length",""),("content-location",""),("content-range",""),("content-type",""),("cookie",""),("date",""),("etag",""),("expect",""),("expires",""),("from",""),("host",""),("if-match",""),("if-modified-since",""),("if-none-match",""),("if-range",""),("if-unmodified-since",""),("last-modified",""),("link",""),("location",""),("max-forwards",""),("proxy-authenticate",""),("proxy-authorization",""),("range",""),("referer",""),("refresh",""),("retry-after",""),("server",""),("set-cookie",""),("strict-transport-security",""),("transfer-encoding",""),("user-agent",""),("vary",""),("via",""),("www-authenticate","")]

UAS = ["Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1","Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1","Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1"]
FPS = [{"l": "zh-CN", "p": "iPhone", "s": "428x926", "c": 4, "touch": True, "tz": "Asia/Shanghai"},{"l": "zh-CN", "p": "iPhone", "s": "390x844", "c": 6, "touch": True, "tz": "Asia/Shanghai"},{"l": "zh-CN", "p": "iPhone", "s": "393x852", "c": 6, "touch": True, "tz": "Asia/Shanghai"},{"l": "zh-CN", "p": "iPhone", "s": "430x932", "c": 6, "touch": True, "tz": "Asia/Shanghai"}]
CH_ERR = ("CHALLENGE_REQUIRED", "CHALLENGE_WRONG", "CHALLENGE_EXPIRED", "CHALLENGE_INVALID")
FATAL = ("BANNED", "BOT_BLOCKED")

def _hpack_int(n, bits, first):
    limit = (1 << bits) - 1
    if n < limit:
        return bytes([first | n])
    out = bytearray([first | limit])
    n -= limit
    while n >= 128:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)

def _hpack_str(s):
    b = s.encode("utf-8")
    if len(b) < 127:
        return bytes([len(b)]) + b
    return _hpack_int(len(b), 7, 0x00) + b

def hpack_encode(headers):
    out = bytearray()
    for name, value in headers:
        name = name.lower()
        exact = None
        for i, (n, v) in enumerate(STATIC, start=1):
            if n == name and v == value:
                exact = i
                break
        if exact is not None:
            out += _hpack_int(exact, 7, 0x80)
            continue
        name_idx = None
        for i, (n, v) in enumerate(STATIC, start=1):
            if n == name and v == "":
                name_idx = i
                break
        if name_idx is not None:
            out += _hpack_int(name_idx, 6, 0x40)
            out += _hpack_str(value)
        else:
            out += b"\x00"
            out += _hpack_str(name)
            out += _hpack_str(value)
    return bytes(out)

def _dec_int(data, i, bits):
    limit = (1 << bits) - 1
    val = data[i] & limit
    i += 1
    if val < limit:
        return val, i
    m = 0
    while i < len(data):
        b = data[i]
        i += 1
        val += (b & 0x7F) << m
        m += 7
        if not (b & 0x80):
            break
    return val, i

def _huff_decode(data):
    out = bytearray()
    cur = 0
    nbits = 0
    for byte in data:
        for k in range(7, -1, -1):
            cur = (cur << 1) | ((byte >> k) & 1)
            nbits += 1
            if (cur, nbits) in HUFF_MAP:
                out.append(HUFF_MAP[(cur, nbits)])
                cur = 0
                nbits = 0
            elif nbits > 30:
                cur = 0
                nbits = 0
    return bytes(out)

def _dec_str(data, i):
    huff = bool(data[i] & 0x80)
    ln, i = _dec_int(data, i, 7)
    raw = data[i:i + ln]
    i += ln
    if huff:
        raw = _huff_decode(raw)
    return raw.decode("utf-8", "replace"), i

class HpackDecoder(object):
    def __init__(self):
        self.dyn = []
    def _add(self, n, v):
        self.dyn.insert(0, (n, v))
        if len(self.dyn) > 4096:
            self.dyn.pop()
    def _lookup(self, idx):
        if 0 < idx <= len(STATIC):
            return STATIC[idx - 1]
        i = idx - len(STATIC) - 1
        if 0 <= i < len(self.dyn):
            return self.dyn[i]
        return ("", "")
    def decode(self, data):
        out = []
        i = 0
        n = len(data)
        while i < n:
            b = data[i]
            if b & 0x80:
                idx, i = _dec_int(data, i, 7)
                out.append(self._lookup(idx))
            elif b & 0x40:
                idx, i = _dec_int(data, i, 6)
                if idx:
                    name = self._lookup(idx)[0]
                    val, i = _dec_str(data, i)
                else:
                    name, i = _dec_str(data, i)
                    val, i = _dec_str(data, i)
                self._add(name, val)
                out.append((name, val))
            elif b & 0x20:
                _, i = _dec_int(data, i, 5)
            else:
                idx, i = _dec_int(data, i, 4)
                if idx:
                    name = self._lookup(idx)[0]
                    val, i = _dec_str(data, i)
                else:
                    name, i = _dec_str(data, i)
                    val, i = _dec_str(data, i)
                out.append((name, val))
        return out

class H2Error(Exception):
    pass

class H2Client(object):
    def __init__(self, host, port=443, timeout=20):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self._stream_id = 1
    def _ctx(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        try:
            ctx.set_alpn_protocols(["h2", "http/1.1"])
        except Exception:
            pass
        return ctx
    def connect(self):
        proxy_url = os.environ.get("PROXY_LIST")
        if proxy_url:
            parsed = urllib.parse.urlparse(proxy_url)
            proxy_host = parsed.hostname
            proxy_port = parsed.port or 80
            proxy_user = parsed.username or ""
            proxy_pass = parsed.password or ""
            raw = socket.create_connection((proxy_host, proxy_port), timeout=self.timeout)
            auth_str = f"{proxy_user}:{proxy_pass}"
            auth_b64 = base64.b64encode(auth_str.encode()).decode()
            connect_req = f"CONNECT {self.host}:{self.port} HTTP/1.1\r\nHost: {self.host}:{self.port}\r\nProxy-Authorization: Basic {auth_b64}\r\n\r\n"
            raw.sendall(connect_req.encode())
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = raw.recv(1024)
                if not chunk:
                    break
                resp += chunk
            if b"200" not in resp.split(b"\r\n")[0]:
                raise H2Error(f"Proxy CONNECT failed: {resp.decode('utf-8', 'ignore')}")
            self.sock = self._ctx().wrap_socket(raw, server_hostname=self.host)
        else:
            raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
            self.sock = self._ctx().wrap_socket(raw, server_hostname=self.host)
        self.sock.sendall(H2_PREFACE)
        self._send_frame(FRAME_SETTINGS, 0, b"")
    def _send_frame(self, ftype, flags, payload, stream=0):
        header = struct.pack(">I", len(payload))[1:] + bytes([ftype, flags]) + struct.pack(">I", stream & 0x7FFFFFFF)
        self.sock.sendall(header + payload)
    def _read_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise H2Error("连接关闭")
            buf += chunk
        return buf
    def _read_frame(self):
        hdr = self._read_exact(9)
        length = struct.unpack(">I", b"\x00" + hdr[:3])[0]
        ftype = hdr[3]
        flags = hdr[4]
        stream = struct.unpack(">I", hdr[5:9])[0] & 0x7FFFFFFF
        payload = self._read_exact(length) if length else b""
        return ftype, flags, stream, payload
    def close(self):
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass

def _hdrs(path, vid):
    fp = random.choice(FPS)
    return [(":method", "GET"), (":scheme", "https"), (":authority", HOST), (":path", BASE_PATH + path),("user-agent", random.choice(UAS)),("x-client-info", urllib.parse.quote(json.dumps(fp, separators=(",", ":")))),("accept", "application/json"),("accept-language", "zh-CN,zh-Hans;q=0.9"),("referer", "https://%s%s/" % (HOST, BASE_PATH)),("origin", "https://%s" % HOST),("sec-fetch-site", "same-origin"),("sec-fetch-mode", "cors"),("sec-fetch-dest", "empty"),("priority", "u=1, i"),("cookie", "ds_vid=" + vid)]

def _one_request(path, vid, timeout=25):
    c = H2Client(HOST, PORT, timeout=timeout)
    try:
        c.connect()
    except Exception as e:
        return {"ok": False, "error": "NETWORK", "message": str(e)}
    try:
        c._send_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, hpack_encode(_hdrs(path, vid)), 1)
        dec = HpackDecoder()
        body = bytearray()
        c.sock.settimeout(timeout)
        deadline = time.time() + timeout
        while time.time() < deadline:
            ft, fl, sid, pl = c._read_frame()
            if ft == FRAME_SETTINGS and not (fl & FLAG_ACK):
                c._send_frame(FRAME_SETTINGS, FLAG_ACK, b"")
                continue
            if ft == FRAME_PING and not (fl & FLAG_ACK):
                c._send_frame(FRAME_PING, FLAG_ACK, pl)
                continue
            if ft == FRAME_GOAWAY:
                break
            if ft in (FRAME_HEADERS, FRAME_CONT):
                dec.decode(pl)
                if fl & FLAG_END_STREAM:
                    break
            elif ft == FRAME_DATA:
                body += pl
                if pl:
                    c._send_frame(FRAME_WINDOW, 0, len(pl).to_bytes(4, "big"), 0)
                    c._send_frame(FRAME_WINDOW, 0, len(pl).to_bytes(4, "big"), sid)
                if fl & FLAG_END_STREAM:
                    break
            elif ft == FRAME_RST:
                break
        if not body:
            return {"ok": False, "error": "EMPTY", "message": "无响应"}
        return json.loads(bytes(body).decode("utf-8", "replace"))
    except Exception as e:
        return {"ok": False, "error": "NETWORK", "message": str(e)}
    finally:
        c.close()

def arith(q):
    m = re.findall(r"\d+", q or "")
    if len(m) < 2:
        return ""
    a, b = int(m[0]), int(m[1])
    if "+" in q:
        return str(a + b)
    if "-" in q or "\u2212" in q:
        return str(a - b)
    if "\u00d7" in q or "*" in q or "x" in q:
        return str(a * b)
    if "\u00f7" in q or "/" in q:
        return str(a // b) if b else "0"
    return str(a + b)

def solve_delta(link):
    path = "/api/solve?url=" + urllib.parse.quote(link, safe="")
    vid = "v_" + os.urandom(8).hex()
    r = _one_request(path, vid, timeout=25)
    if r.get("ok"):
        return r
    if r.get("error") in CH_ERR:
        tok = r.get("token")
        q = r.get("question", "")
        if not tok or not q:
            c = _one_request("/api/challenge", "v_" + os.urandom(8).hex(), 25)
            tok = tok or c.get("token")
            q = q or c.get("question", "")
        ans = arith(q)
        p = ("/api/solve?url=" + urllib.parse.quote(link, safe="") + "&ct=" + urllib.parse.quote(tok or "") + "&ca=" + urllib.parse.quote(ans))
        return _one_request(p, "v_" + os.urandom(8).hex(), 25)
    return r

app = FastAPI()

@app.get("/health")
@app.get("/healthz")
@app.get("/")
def health_check():
    return {"status": "ok"}

@app.get("/delta")
def delta(url: str = Query(...)):
    try:
        data = solve_delta(url)
        if data.get("ok"):
            return {"key": data.get("key", ""), "error": None}
        return {"key": None, "error": str(data.get("error", "solve failed"))}
    except Exception as e:
        return {"key": None, "error": f"solve exception: {type(e).__name__} - {str(e)}"}

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatCompletionRequest(BaseModel):
    model: str
    messages: List[ChatMessage]

@app.post("/v1/chat/completions")
async def chat_completions(req: ChatCompletionRequest):
    user_text = ""
    for msg in req.messages:
        if msg.role == "user":
            user_text = msg.content
            break

    url_match = re.search(r'https?://[^\s]+', user_text)
    if not url_match:
        if "Calculate and respond with ONLY the number" in user_text:
            exprs = re.findall(r'(\d+)\s*([+\-*/])\s*(\d+)\s*=\s*\?', user_text)
            if exprs:
                a, op, b = exprs[-1]
                a, b = int(a), int(b)
                if op == '+':
                    content = str(a + b)
                elif op == '-':
                    content = str(a - b)
                elif op == '*':
                    content = str(a * b)
                else:
                    content = str(a // b) if b else "0"
            else:
                content = user_text
        else:
            content = user_text
    else:
        target = url_match.group(0)
        try:
            result = solve_delta(target)
            if result.get("ok"):
                content = f"解卡成功！\nKey: {result.get('key', '')}"
            else:
                content = f"解卡失败：{result.get('error', '未知错误')}"
        except Exception as e:
            content = f"解卡出错：{str(e)}"

    return {
        "id": "chatcmpl-001",
        "object": "chat.completion",
        "created": 1234567890,
        "model": req.model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
