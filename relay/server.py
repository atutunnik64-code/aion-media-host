"""Short-lived, signed media delivery. Uploads require the platform's token."""
import hashlib
import hmac
import json
import os
import re
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

TTL = 3600
MIMES = {'video/mp4', 'audio/mpeg', 'audio/mp3', 'audio/wav', 'audio/x-wav', 'audio/flac', 'audio/ogg', 'audio/mp4', 'image/png', 'image/jpeg', 'image/webp'}


class MediaServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, root, token, origin):
        if len(token) < 32:
            raise ValueError('Set a token with at least 32 characters')
        u = urlsplit(origin)
        if u.scheme != 'https' or not u.hostname or u.username or u.password or u.query or u.fragment or u.path not in ('', '/'):
            raise ValueError('Set the external HTTPS origin')
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.token, self.origin, self.lock = token, origin.rstrip('/'), threading.RLock()
        super().__init__(address, Handler)

    def signature(self, key, expires):
        return hmac.new(self.token.encode(), f'media-v1\n{key}\n{expires}'.encode(), hashlib.sha256).hexdigest()

    def cleanup(self):
        with self.lock:
            for meta in self.root.glob('*.json'):
                try:
                    expired = json.loads(meta.read_text())['expires'] <= time.time()
                except (ValueError, KeyError):
                    expired = True
                if expired:
                    meta.with_suffix('.bin').unlink(missing_ok=True)
                    meta.unlink(missing_ok=True)


class Handler(BaseHTTPRequestHandler):
    server: MediaServer
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass  # Signed download URLs and authorization never go into logs.

    def reply(self, status, value=None):
        data = json.dumps(value or {'error': 'Request unavailable'}).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.close_connection = True
        if self.command != 'HEAD':
            self.wfile.write(data)

    def key(self):
        match = re.fullmatch(r'/objects/([a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12})', urlsplit(self.path).path)
        return match[1] if match else None

    def authorized(self):
        return hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + self.server.token)

    def do_PUT(self):
        key = self.key()
        if not self.authorized():
            return self.reply(401)
        if not key or urlsplit(self.path).query:
            return self.reply(400)
        try:
            size = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            return self.reply(400)
        mime = self.headers.get('Content-Type', '')
        if self.headers.get('Transfer-Encoding') or self.headers.get('Content-Encoding') or size <= 0 or mime not in MIMES:
            return self.reply(413)
        self.connection.settimeout(45)
        staged = None
        try:
            digest = hashlib.sha256()
            remaining, head = size, b''
            with tempfile.NamedTemporaryFile(dir=self.server.root, delete=False) as temp:
                staged = Path(temp.name)
                while remaining:
                    chunk = self.rfile.read(min(65536, remaining))
                    if not chunk:
                        return self.reply(400)
                    if len(head) < 32:
                        head = (head + chunk)[:32]
                    digest.update(chunk)
                    temp.write(chunk)
                    remaining -= len(chunk)
            valid = head[:8] == b'\x89PNG\r\n\x1a\n' if mime == 'image/png' else (head[:2] == b'\xff\xd8' if mime == 'image/jpeg' else (head[:4] == b'RIFF' and head[8:12] == b'WEBP' if mime == 'image/webp' else (head[4:8] == b'ftyp' if mime in {'video/mp4', 'audio/mp4'} else (
                head[:4] == b'RIFF' and head[8:12] == b'WAVE' if mime in {'audio/wav', 'audio/x-wav'} else
                head[:4] == b'fLaC' if mime == 'audio/flac' else
                head[:4] == b'OggS' if mime == 'audio/ogg' else
                head[:3] == b'ID3' or len(head) > 1 and head[0] == 255 and head[1] & 224 == 224))))
            if not valid:
                return self.reply(415)
            digest = digest.hexdigest()
            with self.server.lock:
                self.server.cleanup()
                target = self.server.root / (key + '.bin')
                metadata = self.server.root / (key + '.json')
                if metadata.exists():
                    old = json.loads(metadata.read_text())
                    if old['sha256'] != digest or old['mime'] != mime:
                        return self.reply(409)
                if not target.exists():
                    staged.replace(target)
                expires = int(time.time()) + TTL
                meta = {'expires': expires, 'sha256': digest, 'mime': mime, 'size': size}
                with tempfile.NamedTemporaryFile(mode='w', dir=self.server.root, delete=False) as temp:
                    json.dump(meta, temp)
                os.replace(temp.name, metadata)
        except (OSError, TimeoutError):
            return self.reply(503)
        finally:
            if staged:
                staged.unlink(missing_ok=True)
        signature = self.server.signature(key, expires)
        self.reply(200, {'url': f'{self.server.origin}/objects/{key}?expires={expires}&signature={signature}', 'expiresAt': expires * 1000})

    def do_GET(self):
        if self.path == '/health':
            return self.reply(200, {'service': 'iskra-media-transfer', 'protocol': 1, 'ready': True})
        key = self.key()
        query = parse_qs(urlsplit(self.path).query)
        try:
            if set(query) != {'signature', 'expires'} or any(len(v) != 1 for v in query.values()):
                raise ValueError()
            expires = int(query['expires'][0])
            allowed = key and time.time() < expires <= time.time() + TTL + 5 and hmac.compare_digest(query['signature'][0], self.server.signature(key, expires))
        except (ValueError, KeyError):
            allowed = False
        if not allowed:
            return self.reply(404)
        with self.server.lock:
            metadata = self.server.root / (key + '.json')
            target = self.server.root / (key + '.bin')
            if not metadata.exists() or not target.exists():
                return self.reply(404)
            meta = json.loads(metadata.read_text())
            if meta['expires'] <= time.time():
                return self.reply(404)
            size = meta['size']
            start, end, partial = 0, size - 1, False
            if self.headers.get('Range'):
                match = re.fullmatch(r'bytes=(\d*)-(\d*)', self.headers['Range'])
                if not match or not any(match.groups()):
                    return self.reply(416)
                if match[1]:
                    start, end = int(match[1]), min(size - 1, int(match[2])) if match[2] else size - 1
                else:
                    start = max(0, size - int(match[2]))
                if not 0 <= start <= end < size:
                    return self.reply(416)
                partial = True
            file = target.open('rb')
            file.seek(start)
        self.send_response(206 if partial else 200)
        self.send_header('Content-Type', meta['mime'])
        self.send_header('Content-Length', str(end - start + 1))
        self.send_header('Accept-Ranges', 'bytes')
        self.send_header('Cache-Control', 'private, no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'none'; sandbox")
        self.send_header('Connection', 'close')
        if partial:
            self.send_header('Content-Range', f'bytes {start}-{end}/{size}')
        self.end_headers()
        self.close_connection = True
        try:
            if self.command != 'HEAD':
                remaining = end - start + 1
                while remaining:
                    chunk = file.read(min(65536, remaining))
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    remaining -= len(chunk)
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            file.close()

    do_HEAD = do_GET

    def do_DELETE(self):
        if not self.authorized():
            return self.reply(401)
        key = self.key()
        if not key:
            return self.reply(400)
        with self.server.lock:
            for extension in ('.bin', '.json'):
                (self.server.root / (key + extension)).unlink(missing_ok=True)
        self.reply(200, {'deleted': True})


if __name__ == '__main__':
    server = MediaServer(('0.0.0.0', int(os.environ.get('PORT', '8789'))), os.environ.get('MEDIA_STORAGE', '/tmp/iskra-media'), os.environ['ISKRA_MEDIA_RELAY_TOKEN'], os.environ.get('ISKRA_MEDIA_RELAY_ORIGIN') or os.environ['RENDER_EXTERNAL_URL'])
    def cleanup_loop():
        while True:
            server.cleanup()
            time.sleep(30)
    threading.Thread(target=cleanup_loop, daemon=True).start()
    server.serve_forever()
