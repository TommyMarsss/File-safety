#!/usr/bin/env python3
"""文件上传服务（仅标准库）。

路由：
  GET  /                前端页面
  GET  /samples/<name>  预置样本（含恶意样本，供前端按钮构造真实上传）
  POST /upload          multipart/form-data 上传，返回 JSON 判定结果
"""
from __future__ import annotations

import base64
import io
import json
import os
import re
import uuid
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import filecheck
from filecheck import Reject

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", BASE_DIR / "uploads"))

# 1x1 透明 PNG
TINY_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAE"
    "hQGAhKmMIQAAAABJRU5ErkJggg=="
)


# ---------------------------------------------------------------- 样本生成

def make_zip_bomb() -> bytes:
    """约 100MB 高度可压缩内容，压缩后仅 ~100KB，压缩比 ~1000:1。"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb.txt", b"A" * (100 * 1024 * 1024))
    return buf.getvalue()


def make_symlink_zip() -> bytes:
    buf = io.BytesIO()
    zi = zipfile.ZipInfo("link.txt")
    zi.external_attr = 0o120777 << 16  # S_IFLNK
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(zi, "/etc/passwd")
    return buf.getvalue()


def make_valid_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("hello.txt", "hello, world\n")
        zf.writestr("docs/readme.txt", "nested file is fine\n")
    return buf.getvalue()


def make_traversal_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../evil.txt", "pwned")
    return buf.getvalue()


SAMPLES = {
    "valid.png": lambda: (TINY_PNG, "image/png"),
    "fake-exe": lambda: (b"MZ\x90\x00" + b"\x00" * 64 + b"This program cannot be run",
                         "application/octet-stream"),
    "valid.zip": lambda: (make_valid_zip(), "application/zip"),
    "zip-bomb.zip": lambda: (make_zip_bomb(), "application/zip"),
    "symlink.zip": lambda: (make_symlink_zip(), "application/zip"),
    "traversal.zip": lambda: (make_traversal_zip(), "application/zip"),
}


# ---------------------------------------------------------------- multipart

_CD_PARAM_RE = re.compile(r';\s*([a-zA-Z-]+)="((?:[^"\\]|\\.)*)"')


def parse_multipart(body: bytes, boundary: bytes):
    """极简 multipart 解析：返回 [(name, filename|None, content)]。"""
    parts = []
    for seg in body.split(b"--" + boundary):
        if seg.startswith(b"\r\n"):
            seg = seg[2:]
        if seg.endswith(b"\r\n"):
            seg = seg[:-2]
        if not seg or seg == b"--":
            continue
        header_blob, sep, content = seg.partition(b"\r\n\r\n")
        if not sep:
            continue
        disposition = ""
        for line in header_blob.split(b"\r\n"):
            if line.lower().startswith(b"content-disposition:"):
                disposition = line.split(b":", 1)[1].decode("utf-8", "replace")
        name_m = re.search(r';\s*name="((?:[^"\\]|\\.)*)"', disposition)
        if not name_m:
            continue
        file_m = _CD_PARAM_RE.search(disposition[len(name_m.group(0)):])
        filename = file_m.group(2) if file_m else None
        parts.append((name_m.group(1), filename, content))
    return parts


# ---------------------------------------------------------------- 上传处理

def handle_upload(filename: str, data: bytes) -> dict:
    """校验并存储，返回结果 dict；校验失败抛 Reject。"""
    result = {"filename": filename}

    safe_name = filecheck.sanitize_filename(filename)
    detected = filecheck.detect_type(data)
    if detected is None:
        raise Reject("无法识别的文件类型（魔数不匹配任何允许的类型）")
    kind, mime, ext = detected
    result["detected_type"] = f"{kind} ({mime})"
    if kind not in filecheck.ALLOWED_KINDS:
        raise Reject(f"文件类型 {kind} 不在允许列表中")

    filecheck.check_extension(safe_name, kind)

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    stored_name = f"{uuid.uuid4().hex}{ext}"  # 存储名由服务端生成
    stored_path = UPLOAD_DIR / stored_name
    stored_path.write_bytes(data)
    result["stored_as"] = stored_name

    if kind == "zip":
        filecheck.validate_zip(data)  # 写盘后、解压前再次把关
        extract_dir = UPLOAD_DIR / stored_path.stem
        extract_dir.mkdir(exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                dest = filecheck.safe_join(str(extract_dir), info.filename)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with zf.open(info) as src, open(dest, "wb") as dst:
                    dst.write(src.read())
        result["extracted_to"] = extract_dir.name + "/"

    result["accepted"] = True
    result["reason"] = "校验通过"
    return result


# ---------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = "SafeUpload/1.0"

    def _json(self, status: int, payload: dict):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _bytes(self, status: int, data: bytes, content_type: str):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):  # 静默默认日志
        pass

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._bytes(200, (STATIC_DIR / "index.html").read_bytes(), "text/html; charset=utf-8")
            return
        m = re.fullmatch(r"/samples/([A-Za-z0-9._-]+)", self.path)
        if m and m.group(1) in SAMPLES:
            data, ctype = SAMPLES[m.group(1)]()
            self._bytes(200, data, ctype)
            return
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/upload":
            self._json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            self._json(400, {"accepted": False, "reason": "请求体为空"})
            return
        if length > filecheck.MAX_UPLOAD_BYTES:
            self._json(413, {"accepted": False,
                             "reason": f"超过 {filecheck.MAX_UPLOAD_BYTES // (1024 * 1024)}MB 上传上限"})
            return
        ctype = self.headers.get("Content-Type", "")
        m = re.match(r"multipart/form-data;\s*boundary=(.+)", ctype)
        if not m:
            self._json(400, {"accepted": False, "reason": "需要 multipart/form-data"})
            return
        body = self.rfile.read(length)
        parts = parse_multipart(body, m.group(1).encode())
        files = [p for p in parts if p[1] is not None]
        if not files:
            self._json(400, {"accepted": False, "reason": "表单中没有文件字段"})
            return
        _, filename, data = files[0]
        try:
            result = handle_upload(filename, data)
        except Reject as e:
            detected = filecheck.detect_type(data)
            payload = {"accepted": False, "reason": str(e), "filename": filename}
            if detected:
                payload["detected_type"] = f"{detected[0]} ({detected[1]})"
            self._json(400, payload)
            return
        self._json(200, result)


def main(port: int = 8000):
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Serving on http://127.0.0.1:{server.server_address[1]}")
    server.serve_forever()


if __name__ == "__main__":
    import sys
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 8000)
