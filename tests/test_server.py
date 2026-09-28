"""server.py 集成测试：真实 HTTP 服务 + 真实 multipart/form-data 请求。"""
import http.client
import json
import os
import sys
import threading
import unittest
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import samples
import server


def encode_multipart(field: str, filename: str, data: bytes) -> tuple[bytes, str]:
    """手工构造 multipart/form-data 请求体。"""
    boundary = "----testboundary" + uuid.uuid4().hex
    lines = [
        f"--{boundary}\r\n".encode(),
        f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'.encode("utf-8"),
        b"Content-Type: application/octet-stream\r\n",
        b"\r\n",
        data,
        b"\r\n",
        f"--{boundary}--\r\n".encode(),
    ]
    return b"".join(lines), boundary


class ServerTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from http.server import ThreadingHTTPServer
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.UploadHandler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def upload(self, filename: str, data: bytes) -> tuple[int, dict]:
        body, boundary = encode_multipart("file", filename, data)
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request(
            "POST", "/upload", body,
            {"Content-Type": f"multipart/form-data; boundary={boundary}",
             "Content-Length": str(len(body))},
        )
        resp = conn.getresponse()
        payload = json.loads(resp.read())
        conn.close()
        return resp.status, payload

    def get(self, path: str) -> tuple[int, bytes, dict]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
        return resp.status, body, headers

    # ---------------------------------------------------------- 用例

    def test_index_page_served(self):
        status, body, _ = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("安全文件上传".encode("utf-8"), body)

    def test_static_traversal_blocked(self):
        status, _, _ = self.get("/static/../server.py")
        self.assertIn(status, (403, 404))

    def test_valid_png_upload_accepted(self):
        _, data, _ = samples.build_sample("valid-png")
        status, v = self.upload("photo.png", data)
        self.assertEqual(status, 200)
        self.assertTrue(v["accepted"], v)
        self.assertEqual(v["detected_type"], "png")
        # 存储名由服务端生成，不含用户文件名
        self.assertNotIn("photo", v["stored_as"])

    def test_valid_zip_uploaded_and_extracted(self):
        _, data, _ = samples.build_sample("valid-zip")
        status, v = self.upload("archive.zip", data)
        self.assertTrue(v["accepted"], v)
        self.assertEqual(len(v["extracted"]), 2)
        for rel in v["extracted"]:
            self.assertFalse(rel.startswith(".."))

    def test_fake_exe_rejected_over_http(self):
        _, data, _ = samples.build_sample("fake-exe-png")
        _, v = self.upload("vacation.png", data)
        self.assertFalse(v["accepted"])
        self.assertTrue(any("可执行文件" in r for r in v["reasons"]))

    def test_traversal_filename_rejected_over_http(self):
        _, data, _ = samples.build_sample("valid-png")
        _, v = self.upload("../../tmp/evil.png", data)
        self.assertFalse(v["accepted"])

    def test_zip_bomb_rejected_over_http(self):
        _, data, _ = samples.build_sample("zip-bomb")
        _, v = self.upload("gift.zip", data)
        self.assertFalse(v["accepted"])
        self.assertTrue(any("压缩比" in r or "超过" in r for r in v["reasons"]))

    def test_sample_endpoint_serves_bytes(self):
        status, body, headers = self.get("/api/samples/valid-png")
        self.assertEqual(status, 200)
        self.assertTrue(body.startswith(b"\x89PNG"))

    def test_unknown_sample_404(self):
        status, _, _ = self.get("/api/samples/nope")
        self.assertEqual(status, 404)

    def test_oversize_request_rejected_413(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request(
            "POST", "/upload", b"x" * 1024,
            {"Content-Type": "multipart/form-data; boundary=x",
             "Content-Length": str(server.security.MAX_UPLOAD_SIZE + 200 * 1024)},
        )
        resp = conn.getresponse()
        resp.read()
        conn.close()
        self.assertEqual(resp.status, 413)


if __name__ == "__main__":
    unittest.main()
