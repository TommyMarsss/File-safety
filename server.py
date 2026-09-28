#!/usr/bin/env python3
"""文件上传服务（仅标准库）。

路由：
  GET  /                     前端页面
  GET  /static/<path>        前端静态资源
  GET  /api/samples          样本列表
  GET  /api/samples/<key>    下载某个样本的原始字节（前端再将其作为文件上传）
  POST /upload               multipart/form-data 上传，字段名 file

运行：python3 server.py [port]   （默认 8000）
"""
from __future__ import annotations

import json
import os
import sys
import uuid
from email.parser import BytesParser
from email.policy import default as email_policy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse

import samples
import security

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")

# multipart 开销余量（边界、头部等）
MULTIPART_OVERHEAD = 64 * 1024

_MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".png": "image/png",
    ".ico": "image/x-icon",
}


def parse_multipart(content_type: str, body: bytes) -> dict[str, tuple[str, bytes]]:
    """用标准库 email 解析 multipart/form-data。

    返回 {字段名: (文件名, 内容)}；普通字段文件名为空串。
    """
    if "multipart/form-data" not in content_type:
        raise ValueError("Content-Type 不是 multipart/form-data")
    raw = (
        b"Content-Type: " + content_type.encode("latin-1")
        + b"\r\nMIME-Version: 1.0\r\n\r\n" + body
    )
    msg = BytesParser(policy=email_policy).parsebytes(raw)
    if not msg.is_multipart():
        raise ValueError("请求体不是合法的 multipart 数据")
    parts: dict[str, tuple[str, bytes]] = {}
    for part in msg.iter_parts():
        disposition = part.get("Content-Disposition", "")
        if "form-data" not in disposition:
            continue
        name = part.get_param("name", header="Content-Disposition") or ""
        filename = part.get_filename() or ""
        payload = part.get_payload(decode=True) or b""
        parts[name] = (filename, payload)
    return parts


class UploadHandler(BaseHTTPRequestHandler):
    server_version = "SecureUpload/1.0"
    protocol_version = "HTTP/1.1"

    # ------------------------------------------------------------ 工具

    def _send(self, status: int, body: bytes, content_type: str,
              extra_headers: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, obj: dict, status: int = 200,
                   extra_headers: dict | None = None) -> None:
        self._send(status, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8", extra_headers)

    def log_message(self, fmt: str, *args) -> None:  # 保持简洁的一行日志
        sys.stderr.write("[server] %s %s\n" % (self.address_string(), fmt % args))

    # ------------------------------------------------------------ GET

    def do_GET(self) -> None:
        path = unquote(urlparse(self.path).path)
        if path == "/":
            return self._serve_static_file("index.html")
        if path.startswith("/static/"):
            return self._serve_static_file(path[len("/static/"):])
        if path == "/api/samples":
            listing = [
                {"key": key, "filename": fn, "description": desc}
                for key, (fn, desc, _) in samples.SAMPLES.items()
            ]
            return self._send_json({"samples": listing})
        if path.startswith("/api/samples/"):
            key = path[len("/api/samples/"):]
            try:
                filename, data, desc = samples.build_sample(key)
            except KeyError:
                return self._send_json({"error": "未知样本"}, 404)
            return self._send(
                200, data, "application/octet-stream",
                {
                    # 文件名可能含非 ASCII / 路径字符，用 RFC 5987 编码传递
                    "X-Sample-Filename": "UTF-8''" + _rfc5987(filename),
                    "X-Sample-Description": "UTF-8''" + _rfc5987(desc),
                },
            )
        return self._send_json({"error": "not found"}, 404)

    def _serve_static_file(self, rel: str) -> None:
        # 静态目录同样防路径穿越
        rel = rel.replace("\\", "/").lstrip("/")
        if ".." in rel.split("/"):
            return self._send_json({"error": "forbidden"}, 403)
        full = os.path.realpath(os.path.join(STATIC_DIR, rel))
        if os.path.commonpath([os.path.realpath(STATIC_DIR), full]) != os.path.realpath(STATIC_DIR):
            return self._send_json({"error": "forbidden"}, 403)
        if not os.path.isfile(full):
            return self._send_json({"error": "not found"}, 404)
        ext = os.path.splitext(full)[1].lower()
        with open(full, "rb") as f:
            self._send(200, f.read(), _MIME.get(ext, "application/octet-stream"))

    # ------------------------------------------------------------ POST

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path != "/upload":
            return self._send_json({"error": "not found"}, 404)

        # 在读请求体之前先按 Content-Length 拒绝超大上传
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self._send_json({"accepted": False, "reasons": ["缺少 Content-Length"]}, 411)
        if length > security.MAX_UPLOAD_SIZE + MULTIPART_OVERHEAD:
            # 不读请求体直接拒绝；关闭连接避免残留字节被解析成下一个请求
            self.close_connection = True
            return self._send_json(
                {"accepted": False,
                 "reasons": [f"请求体 {length} 字节超过上传上限"]},
                413,
                {"Connection": "close"},
            )

        body = self.rfile.read(length)
        content_type = self.headers.get("Content-Type", "")
        try:
            parts = parse_multipart(content_type, body)
        except ValueError as exc:
            return self._send_json({"accepted": False, "reasons": [str(exc)]}, 400)

        if "file" not in parts or not parts["file"][0]:
            return self._send_json(
                {"accepted": False, "reasons": ["缺少 file 字段或文件名"]}, 400)

        filename, data = parts["file"]
        verdict = security.validate_upload(filename, data)
        result = verdict.to_dict()

        if verdict.accepted:
            # 存储名完全由服务端生成，用户输入不影响落盘路径
            ext = os.path.splitext(filename)[1].lower()
            stored_name = f"{uuid.uuid4().hex}{ext}"
            stored_path = os.path.join(UPLOAD_DIR, stored_name)
            os.makedirs(UPLOAD_DIR, exist_ok=True)
            with open(stored_path, "wb") as f:
                f.write(data)
            result["stored_as"] = stored_name

            if verdict.detected_type == "zip":
                extract_dir = os.path.join(UPLOAD_DIR, "extracted", uuid.uuid4().hex)
                try:
                    written = security.extract_zip_safely(data, extract_dir)
                    result["extracted"] = [
                        os.path.relpath(p, UPLOAD_DIR) for p in written
                    ]
                except ValueError as exc:  # 双重防护触发，理论上不可达
                    os.remove(stored_path)
                    result["accepted"] = False
                    result["reasons"] = [f"解压阶段二次校验失败：{exc}"]
                    return self._send_json(result, 200)

        self._send_json(result, 200)


def _rfc5987(value: str) -> str:
    from urllib.parse import quote
    return quote(value.encode("utf-8"))


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    server = ThreadingHTTPServer(("127.0.0.1", port), UploadHandler)
    print(f"Serving on http://127.0.0.1:{port}  (Ctrl+C 停止)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
