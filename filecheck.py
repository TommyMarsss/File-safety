"""上传安全校验核心模块（仅使用 Python 标准库）。

防护目标：
1. 按魔数（magic bytes）识别真实文件类型，不信任扩展名 / Content-Type。
2. 拒绝路径穿越文件名，存储路径不受用户输入影响。
3. ZIP 解压缩炸弹检测：压缩比、解压后总大小、符号链接、嵌套深度，
   全部在写盘之前完成检查。
"""
from __future__ import annotations

import io
import os
import re
import zipfile

# ---------------------------------------------------------------- 限制常量

MAX_UPLOAD_BYTES = 64 * 1024 * 1024          # 单次上传原始字节上限
MAX_ZIP_ENTRIES = 512                        # 单个 zip 最大条目数（含嵌套累计）
MAX_ZIP_TOTAL_UNCOMPRESSED = 32 * 1024 * 1024  # 解压后总大小上限（含嵌套累计）
MAX_ZIP_RATIO = 100.0                        # 单条目 解压大小/压缩大小 上限
MAX_ZIP_NESTING = 2                          # zip 套 zip 的最大层数


class Reject(Exception):
    """校验不通过。消息面向用户，可直接返回。"""


# ---------------------------------------------------------------- 魔数识别

# (前缀, 类型名, MIME, 标准扩展名)。顺序即匹配优先级。
_SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", "png",  "image/png",  ".png"),
    (b"\xff\xd8\xff",      "jpg",  "image/jpeg", ".jpg"),
    (b"GIF87a",            "gif",  "image/gif",  ".gif"),
    (b"GIF89a",            "gif",  "image/gif",  ".gif"),
    (b"BM",                "bmp",  "image/bmp",  ".bmp"),
    (b"%PDF-",             "pdf",  "application/pdf", ".pdf"),
    (b"PK\x03\x04",        "zip",  "application/zip", ".zip"),
    (b"PK\x05\x06",        "zip",  "application/zip", ".zip"),  # 空 zip
]

# 允许上传的类型。未列出的（如 MZ 可执行文件）一律拒绝。
ALLOWED_KINDS = {"png", "jpg", "gif", "bmp", "webp", "pdf", "zip"}

_KIND_INFO = {kind: (mime, ext) for _, kind, mime, ext in _SIGNATURES}
_KIND_INFO["webp"] = ("image/webp", ".webp")


def detect_type(data: bytes):
    """按魔数识别类型，返回 (kind, mime, ext)；无法识别返回 None。"""
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return ("webp",) + _KIND_INFO["webp"]
    for sig, kind, mime, ext in _SIGNATURES:
        if data.startswith(sig):
            return (kind, mime, ext)
    return None


def check_extension(filename: str, kind: str):
    """扩展名必须与魔数识别出的真实类型一致，否则拒绝。"""
    ext = os.path.splitext(filename)[1].lower()
    expected = _KIND_INFO[kind][1]
    valid = {expected}
    if kind == "jpg":
        valid.add(".jpeg")
    if ext not in valid:
        raise Reject(
            f"扩展名 {ext or '(无)'} 与文件真实类型 {kind}（应为 {expected}）不一致"
        )


# ---------------------------------------------------------------- 文件名消毒

_DRIVE_RE = re.compile(r"^[A-Za-z]:")


def sanitize_filename(name: str) -> str:
    """严格校验用户提交的文件名。

    策略是「拒绝」而非「静默改写」：任何含路径语义的构造都直接拒绝，
    让攻击尝试在日志和前端可见。通过校验的返回值是不含分隔符的纯文件名。
    """
    if not name:
        raise Reject("文件名为空")
    if "\x00" in name:
        raise Reject("文件名包含 NUL 字节")
    if len(name) > 255:
        raise Reject("文件名过长")
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or _DRIVE_RE.match(normalized):
        raise Reject(f"拒绝绝对路径文件名: {name!r}")
    if "/" in normalized:
        # 含任何分隔符（含 ../ 、./ 、子目录）一律拒绝
        raise Reject(f"拒绝包含路径分隔符的文件名（疑似路径穿越）: {name!r}")
    if normalized in (".", ".."):
        raise Reject(f"拒绝特殊文件名: {name!r}")
    return name


# ---------------------------------------------------------------- ZIP 检查

def _check_entry_name(name: str):
    n = name.replace("\\", "/")
    if n.startswith("/") or _DRIVE_RE.match(n):
        raise Reject(f"ZIP 内含绝对路径条目: {name!r}")
    if ".." in n.split("/"):
        raise Reject(f"ZIP 内含路径穿越条目: {name!r}")


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    # Unix 模式下文件类型存在 external_attr 高 16 位；0o120000 = S_IFLNK
    return (info.external_attr >> 16) & 0o170000 == 0o120000


def validate_zip(data: bytes, _depth: int = 0, _stats: dict | None = None):
    """在写盘前递归检查 zip。任何一项不通过即抛出 Reject。

    所有判定只依赖中央目录元数据和有限的嵌套读取，
    不会真正把炸弹内容解压到磁盘或内存（嵌套 zip 的读取受总大小预算约束）。
    """
    if _depth > MAX_ZIP_NESTING:
        raise Reject(f"ZIP 嵌套层级超过 {MAX_ZIP_NESTING} 层")
    if _stats is None:
        _stats = {"entries": 0, "total": 0}

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise Reject("ZIP 结构损坏或格式非法")

    infos = zf.infolist()
    _stats["entries"] += len(infos)
    if _stats["entries"] > MAX_ZIP_ENTRIES:
        raise Reject(f"ZIP 条目数超过上限 {MAX_ZIP_ENTRIES}")

    for info in infos:
        name = info.filename
        _check_entry_name(name)

        if _is_symlink(info):
            raise Reject(f"ZIP 内含符号链接条目: {name!r}")
        if info.flag_bits & 0x1:
            raise Reject(f"ZIP 内含加密条目（无法检查内容）: {name!r}")
        if info.is_dir():
            continue

        _stats["total"] += info.file_size
        if _stats["total"] > MAX_ZIP_TOTAL_UNCOMPRESSED:
            raise Reject(
                f"解压后总大小超过 {MAX_ZIP_TOTAL_UNCOMPRESSED // (1024 * 1024)}MB 上限"
                f"（条目 {name!r} 触发）"
            )

        if info.file_size > 0:
            ratio = info.file_size / max(info.compress_size, 1)
            if ratio > MAX_ZIP_RATIO:
                raise Reject(
                    f"条目 {name!r} 压缩比异常（{ratio:.0f}:1，"
                    f"上限 {MAX_ZIP_RATIO:.0f}:1），疑似压缩炸弹"
                )

        # 嵌套 zip：按魔数识别后递归检查。读取量已被上面的总大小预算约束。
        with zf.open(info) as f:
            head = f.read(4)
            if head[:2] == b"PK":
                nested = head + f.read(MAX_ZIP_TOTAL_UNCOMPRESSED + 1)
                if len(nested) > MAX_ZIP_TOTAL_UNCOMPRESSED:
                    raise Reject(f"嵌套 ZIP {name!r} 超过大小预算")
                validate_zip(nested, _depth + 1, _stats)


def safe_join(base: str, name: str) -> str:
    """把（已通过 _check_entry_name 的）相对路径拼到 base 下，纵深防御：
    解析符号链接后仍必须落在 base 内部。"""
    base_real = os.path.realpath(base)
    dest = os.path.realpath(os.path.join(base_real, name))
    if dest != base_real and not dest.startswith(base_real + os.sep):
        raise Reject(f"解压目标越界: {name!r}")
    return dest
