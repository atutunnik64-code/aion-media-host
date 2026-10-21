import http.client
import json
import tempfile
import threading
import unittest
import uuid
from pathlib import Path
from urllib.parse import urlsplit
from server import MediaServer


class MediaTransferTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.token = 'local-test-secret-' * 3
        self.server = MediaServer(('127.0.0.1', 0), self.temp.name, self.token, 'https://media.example.com')
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.data = b'\x00\x00\x00\x18ftypisom\x00\x00\x00\x00isommp42'
        self.key = str(uuid.uuid4())

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()

    def request(self, method, path, data=None, headers=None):
        c = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        try:
            c.request(method, path, body=data, headers=headers or {})
            r = c.getresponse()
            return r.status, dict(r.headers), r.read()
        finally:
            c.close()

    def upload(self, data=None, key=None):
        return self.request('PUT', '/objects/' + (key or self.key), data or self.data, {'Authorization': 'Bearer ' + self.token, 'Content-Type': 'video/mp4'})

    def signed_path(self):
        status, _, raw = self.upload()
        self.assertEqual(status, 200)
        body = json.loads(raw)
        self.assertNotIn(self.token, body['url'])
        parsed = urlsplit(body['url'])
        return parsed.path + '?' + parsed.query

    def test_upload_requires_auth_and_signed_get_supports_range_and_head(self):
        self.assertEqual(self.request('PUT', '/objects/' + self.key, self.data, {'Content-Type': 'video/mp4'})[0], 401)
        path = self.signed_path()
        self.assertEqual(self.request('GET', '/objects/' + self.key)[0], 404)
        status, headers, data = self.request('GET', path)
        self.assertEqual((status, data, headers['Content-Type']), (200, self.data, 'video/mp4'))
        self.assertEqual(self.request('HEAD', path)[2], b'')
        status, headers, data = self.request('GET', path, headers={'Range': 'bytes=4-7'})
        self.assertEqual((status, data, headers['Content-Range']), (206, b'ftyp', f'bytes 4-7/{len(self.data)}'))
        self.assertEqual(self.request('GET', path, headers={'Range': 'bytes=-4'})[2], b'mp42')
        self.assertEqual(self.request('GET', path, headers={'Range': 'bytes=99-100'})[0], 416)
        self.assertEqual(self.request('GET', path, headers={'Range': 'bytes=1-2,4-7'})[0], 416)

    def test_idempotent_put_cannot_replace_original_or_reuse_signature(self):
        path = self.signed_path()
        self.assertEqual(self.upload()[0], 200)
        self.assertEqual(self.upload(self.data + b'changed')[0], 409)
        self.assertEqual(self.request('GET', path)[2], self.data)
        other = str(uuid.uuid4())
        self.assertEqual(self.upload(key=other)[0], 200)
        self.assertEqual(self.request('GET', path.replace(self.key, other))[0], 404)
        self.assertEqual(self.request('GET', path + '&signature=fake')[0], 404)

    def test_expired_and_deleted_files_are_inaccessible(self):
        path = self.signed_path()
        meta = Path(self.temp.name) / (self.key + '.json')
        data = json.loads(meta.read_text())
        data['expires'] = 1
        meta.write_text(json.dumps(data))
        self.assertEqual(self.request('GET', path)[0], 404)
        self.server.cleanup()
        self.assertFalse(meta.exists())
        self.assertEqual(self.upload()[0], 200)
        self.assertEqual(self.request('DELETE', '/objects/' + self.key)[0], 401)
        self.assertEqual(self.request('DELETE', '/objects/' + self.key, headers={'Authorization': 'Bearer ' + self.token})[0], 200)
        self.assertEqual(self.request('GET', path)[0], 404)

    def test_invalid_payload_and_path_rejected(self):
        self.assertEqual(self.upload(b'not a video')[0], 415)
        self.assertEqual(self.upload(key='../outside')[0], 400)
        self.assertEqual(self.request('PUT', '/objects/' + self.key, headers={'Authorization': 'Bearer ' + self.token, 'Content-Type': 'video/mp4', 'Content-Length': '0'})[0], 413)

    def test_image_output_is_downloadable_without_an_account_or_service_token(self):
        data = b'\x89PNG\r\n\x1a\nfixture'
        status, _, raw = self.request('PUT', '/objects/' + self.key, data, {'Authorization': 'Bearer ' + self.token, 'Content-Type': 'image/png'})
        self.assertEqual(status, 200)
        url = urlsplit(json.loads(raw)['url'])
        status, headers, result = self.request('GET', url.path + '?' + url.query)
        self.assertEqual((status, result, headers['Content-Type']), (200, data, 'image/png'))
        self.assertIn('sandbox', headers['Content-Security-Policy'])


if __name__ == '__main__':
    unittest.main()
