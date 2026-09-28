"""端到端测试：真实 HTTP multipart 上传，覆盖接受/拒绝各路径。

运行: python3 -m unittest tests.test_upload -v
"""
import http.client
import io
import json
import os
import tempfile
import threading
import unittest
import zipfile

os.environ["UPLOAD_DIR"] = tempfile.mkdtemp(prefix="safe-upload-test-")

import server  # noqa: E402

TINY_PNG = server.TINY_PNG


def multipart(field, filename, data, boundary="----testboundary9f8d"):
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode()
    tail = f"\r\n--{boundary}--\r\n".encode()
    return head + data + tail, boundary


class UploadTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def upload(self, filename, data):
        body, boundary = multipart("file", filename, data)
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("POST", "/upload", body, {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(body)),
        })
        resp = conn.getresponse()
        payload = json.loads(resp.read())
        conn.close()
        return resp.status, payload

    # ---------------------------------------------------------- 合法文件

    def test_valid_png_accepted(self):
        status, r = self.upload("photo.png", TINY_PNG)
        self.assertEqual(status, 200)
        self.assertTrue(r["accepted"])
        self.assertIn("png", r["detected_type"])
        self.assertTrue(r["stored_as"].endswith(".png"))
        # 存储名由服务端生成，不含用户输入
        self.assertNotIn("photo", r["stored_as"])

    def test_valid_zip_accepted_and_extracted(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("hello.txt", "hi")
        status, r = self.upload("docs.zip", buf.getvalue())
        self.assertEqual(status, 200)
        self.assertTrue(r["accepted"])
        self.assertIn("extracted_to", r)

    # ---------------------------------------------------------- 魔数校验

    def test_fake_exe_with_png_extension_rejected(self):
        exe = b"MZ\x90\x00" + b"\x00" * 64 + b"payload"
        status, r = self.upload("photo.png", exe)
        self.assertEqual(status, 400)
        self.assertFalse(r["accepted"])
        self.assertIn("无法识别", r["reason"])

    def test_extension_mismatch_rejected(self):
        # 真实 PNG 内容但伪装成 .gif
        status, r = self.upload("photo.gif", TINY_PNG)
        self.assertEqual(status, 400)
        self.assertFalse(r["accepted"])
        self.assertIn("不一致", r["reason"])

    # ---------------------------------------------------------- 路径穿越

    def test_dotdot_filename_rejected(self):
        status, r = self.upload("../../etc/evil.png", TINY_PNG)
        self.assertEqual(status, 400)
        self.assertFalse(r["accepted"])
        self.assertIn("路径", r["reason"])

    def test_absolute_path_filename_rejected(self):
        status, r = self.upload("/etc/passwd.png", TINY_PNG)
        self.assertEqual(status, 400)
        self.assertFalse(r["accepted"])

    def test_windows_path_filename_rejected(self):
        status, r = self.upload("..\\..\\evil.png", TINY_PNG)
        self.assertEqual(status, 400)
        self.assertFalse(r["accepted"])

    def test_zip_with_traversal_entry_rejected(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../../evil.txt", "pwned")
        status, r = self.upload("trav.zip", buf.getvalue())
        self.assertEqual(status, 400)
        self.assertFalse(r["accepted"])
        self.assertIn("路径穿越", r["reason"])

    # ---------------------------------------------------------- 压缩炸弹

    def test_zip_bomb_rejected_at_detection_stage(self):
        bomb = server.make_zip_bomb()
        # 炸弹本体很小（~100KB），但解压后 100MB
        self.assertLess(len(bomb), 1024 * 1024)
        status, r = self.upload("bomb.zip", bomb)
        self.assertEqual(status, 400)
        self.assertFalse(r["accepted"])
        self.assertTrue("压缩比" in r["reason"] or "总大小" in r["reason"])
        # 检测阶段拒绝后服务仍健康：合法文件照常上传
        status2, r2 = self.upload("after.png", TINY_PNG)
        self.assertEqual(status2, 200)
        self.assertTrue(r2["accepted"])

    def test_symlink_zip_rejected(self):
        status, r = self.upload("links.zip", server.make_symlink_zip())
        self.assertEqual(status, 400)
        self.assertFalse(r["accepted"])
        self.assertIn("符号链接", r["reason"])

    def test_nested_zip_bomb_rejected(self):
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("b.txt", b"B" * (40 * 1024 * 1024))
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("inner.zip", inner.getvalue())
        status, r = self.upload("nested.zip", outer.getvalue())
        self.assertEqual(status, 400)
        self.assertFalse(r["accepted"])


if __name__ == "__main__":
    unittest.main()
