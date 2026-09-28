"""服务端样本生成器：为前端演示按钮提供合法/恶意样本字节。

所有样本在内存中即时构造，不依赖磁盘文件。
"""
from __future__ import annotations

import base64
import io
import zipfile

# 1x1 像素 PNG（合法样本）
_VALID_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)


def _make_zip_bomb() -> bytes:
    """构造压缩炸弹：60MB 高度可重复数据，压缩后仅约 60KB，压缩比约 1000:1。"""
    buf = io.BytesIO()
    payload = b"0" * (60 * 1024 * 1024)
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.writestr("bomb.txt", payload)
    return buf.getvalue()


def _make_symlink_zip() -> bytes:
    """构造包含符号链接的 zip，链接目标指向 /etc/passwd。"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("innocent-link")
        # Unix: external_attr 高 16 位为 st_mode，0o120777 = 符号链接
        info.external_attr = 0o120777 << 16
        info.create_system = 3  # Unix
        zf.writestr(info, "/etc/passwd")
        zf.writestr("readme.txt", "this archive hides a symlink\n")
    return buf.getvalue()


def _make_traversal_zip() -> bytes:
    """构造成员名含 ../ 的 zip（Zip Slip 样本）。"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../tmp/evil.txt", "pwned\n")
        zf.writestr("ok.txt", "harmless\n")
    return buf.getvalue()


def _make_valid_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("hello.txt", "hello, world\n")
        zf.writestr("docs/readme.md", "# readme\n")
    return buf.getvalue()


def _make_fake_png() -> bytes:
    """Windows PE 可执行文件头，但会被命名为 .png 上传。"""
    # MZ 头 + 伪造的 DOS stub + PE 签名区域，足以触发魔数识别
    return (
        b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        b"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
        + b"\x00" * 32
        + b"PE\x00\x00" + b"\x4c\x01" + b"\x00" * 200
    )


def _make_fake_jpg() -> bytes:
    """ELF 可执行文件头，命名为 .jpg 上传。"""
    return b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 120


SAMPLES: dict[str, tuple[str, str, callable]] = {
    # key: (生成的文件名, 说明, 构造函数)
    "valid-png": ("photo.png", "合法 PNG 图片", lambda: _VALID_PNG),
    "valid-zip": ("archive.zip", "合法 ZIP 压缩包", _make_valid_zip),
    "fake-exe-png": ("vacation.png", "伪造 .png 扩展名的 PE 可执行文件", _make_fake_png),
    "fake-elf-jpg": ("avatar.jpg", "伪造 .jpg 扩展名的 ELF 可执行文件", _make_fake_jpg),
    "traversal-name": ("../../tmp/evil.png", "文件名含 ../ 路径穿越（内容为合法 PNG）", lambda: _VALID_PNG),
    "abs-name": ("/etc/cron.d/backdoor.png", "文件名为绝对路径（内容为合法 PNG）", lambda: _VALID_PNG),
    "zip-bomb": ("gift.zip", "ZIP 压缩炸弹（压缩比约 1000:1）", _make_zip_bomb),
    "zip-symlink": ("backup.zip", "包含指向 /etc/passwd 符号链接的 ZIP", _make_symlink_zip),
    "zip-traversal": ("update.zip", "成员名含 ../../ 的 ZIP（Zip Slip）", _make_traversal_zip),
}


def build_sample(key: str) -> tuple[str, bytes, str]:
    """返回 (文件名, 内容字节, 说明)。key 不存在抛 KeyError。"""
    filename, desc, factory = SAMPLES[key]
    return filename, factory(), desc
