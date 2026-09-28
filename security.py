"""上传内容安全校验核心。

仅使用 Python 标准库。校验顺序（任一失败即拒绝，全部通过才落盘）：

1. 大小限制（空文件 / 超过上限）
2. 文件名清洗（路径穿越、绝对路径、NUL 字节、非法字符）
3. 可执行文件魔数拦截（PE / ELF / Mach-O / shebang 脚本）
4. 真实类型识别（magic bytes，而非扩展名或 Content-Type）
5. 扩展名与真实类型一致性（声称是图片但内容不是 -> 拒绝）
6. ZIP 安全分析（只读中央目录元数据，不解压、不写盘）：
   - 条目数上限
   - 解压后单文件 / 总大小上限
   - 压缩比异常（炸弹特征）
   - 符号链接条目
   - 成员名路径穿越 / 绝对路径
   - 嵌套压缩包
"""
from __future__ import annotations

import io
import os
import re
import stat
import zipfile
from dataclasses import dataclass, field

# ---------------------------------------------------------------- 限制常量

MAX_UPLOAD_SIZE = 25 * 1024 * 1024            # 单个上传文件最大 25 MB
MAX_ZIP_ENTRIES = 200                          # 压缩包内最大条目数
MAX_ZIP_TOTAL_UNCOMPRESSED = 100 * 1024 * 1024  # 解压后总大小上限 100 MB
MAX_ZIP_MEMBER_UNCOMPRESSED = 50 * 1024 * 1024  # 解压后单条目上限 50 MB
MAX_COMPRESSION_RATIO = 100.0                  # 单条目压缩比上限
RATIO_CHECK_MIN_COMPRESSED = 1024              # 压缩后小于 1KB 的条目不做压缩比判定
ALLOW_NESTED_ARCHIVES = False                  # 是否允许压缩包内再嵌套压缩包

ALLOWED_TYPES = {"png", "jpeg", "gif", "bmp", "webp", "pdf", "zip"}

EXT_TO_TYPE = {
    ".png": "png",
    ".jpg": "jpeg",
    ".jpeg": "jpeg",
    ".gif": "gif",
    ".bmp": "bmp",
    ".webp": "webp",
    ".pdf": "pdf",
    ".zip": "zip",
}

# ---------------------------------------------------------------- 判定结果


@dataclass
class Verdict:
    accepted: bool
    reasons: list[str] = field(default_factory=list)
    detected_type: str | None = None
    original_filename: str = ""

    def to_dict(self) -> dict:
        return {
            "accepted": self.accepted,
            "reasons": self.reasons,
            "detected_type": self.detected_type,
            "original_filename": self.original_filename,
        }


# ---------------------------------------------------------------- 魔数识别


def detect_file_type(data: bytes) -> str | None:
    """根据文件头魔数识别真实类型，识别不了返回 None。"""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if data.startswith(b"BM"):
        return "bmp"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if data.startswith(b"%PDF-"):
        return "pdf"
    # PK\x03\x04 普通条目；PK\x05\x06 空压缩包（只有 EOCD）
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
        return "zip"
    return None


_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",  # 32-bit
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",  # 64-bit
    b"\xca\xfe\xba\xbe",                       # universal / fat
}


def detect_executable(data: bytes) -> str | None:
    """识别可执行文件 / 脚本，返回描述；不是则返回 None。"""
    if data.startswith(b"MZ"):
        return "Windows PE 可执行文件 (MZ 头)"
    if data.startswith(b"\x7fELF"):
        return "ELF 可执行文件"
    if data[:4] in _MACHO_MAGICS:
        return "Mach-O 可执行文件"
    if data.startswith(b"#!"):
        return "脚本文件 (shebang 头)"
    return None


# ---------------------------------------------------------------- 文件名清洗

_SAFE_CHARS = re.compile(r"[^A-Za-z0-9._\- ]")
_DRIVE_LETTER = re.compile(r"^[A-Za-z]:")


def check_filename(name: str) -> list[str]:
    """检查用户提交的文件名，返回问题列表（空列表 = 安全）。

    策略是「拒绝」而非「尝试修复」：任何路径构造痕迹都直接判负，
    避免不同操作系统对分隔符/特殊名解析差异造成的绕过。
    """
    problems: list[str] = []
    if not name:
        problems.append("文件名为空")
        return problems
    if "\x00" in name:
        problems.append("文件名包含 NUL 字节")
    if "/" in name or "\\" in name:
        problems.append("文件名包含路径分隔符（疑似路径穿越）")
    if name in (".", "..") or ".." in name.split("/") or ".." in name.split("\\"):
        problems.append("文件名包含 '..' 父目录引用（路径穿越）")
    if name.startswith("/") or name.startswith("\\") or _DRIVE_LETTER.match(name):
        problems.append("文件名是绝对路径（路径穿越）")
    if name.startswith("."):
        problems.append("文件名以 '.' 开头（隐藏文件）")
    if _SAFE_CHARS.search(name):
        problems.append("文件名包含非法字符（仅允许字母、数字、. _ - 和空格）")
    if os.path.basename(name) != name:
        problems.append("文件名经系统规范化后发生变化（不可信）")
    return problems


# ---------------------------------------------------------------- ZIP 分析


def analyze_zip(data: bytes) -> list[str]:
    """只读取 ZIP 中央目录元数据做炸弹/穿越检测，不解压任何内容。

    返回问题列表（空列表 = 通过）。所有判定都发生在写盘之前。
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return ["ZIP 结构损坏或中央目录无法解析"]

    problems: list[str] = []
    infos = zf.infolist()

    if len(infos) > MAX_ZIP_ENTRIES:
        problems.append(f"条目数 {len(infos)} 超过上限 {MAX_ZIP_ENTRIES}")

    total_uncompressed = 0
    for info in infos:
        name = info.filename

        # 成员名路径穿越 / 绝对路径
        if name.startswith("/") or _DRIVE_LETTER.match(name):
            problems.append(f"成员 {name!r} 是绝对路径")
        normalized = name.replace("\\", "/")
        if ".." in normalized.split("/"):
            problems.append(f"成员 {name!r} 包含 '..' 路径穿越")
        if "\x00" in name:
            problems.append(f"成员 {name!r} 包含 NUL 字节")

        # 符号链接（Unix 模式下 external_attr 高 16 位是 st_mode）
        mode = info.external_attr >> 16
        if stat.S_ISLNK(mode):
            problems.append(f"成员 {name!r} 是符号链接，可能指向压缩包外部")

        # 嵌套压缩包
        if not ALLOW_NESTED_ARCHIVES and name.lower().endswith(".zip"):
            problems.append(f"成员 {name!r} 是嵌套压缩包（不允许，防止递归炸弹）")

        # 解压后大小（元数据声明值，炸弹在此现形）
        total_uncompressed += info.file_size
        if info.file_size > MAX_ZIP_MEMBER_UNCOMPRESSED:
            problems.append(
                f"成员 {name!r} 解压后 {info.file_size} 字节，"
                f"超过单条目上限 {MAX_ZIP_MEMBER_UNCOMPRESSED}"
            )

        # 压缩比异常（小文件天然压缩比高，设下限避免误伤）
        if info.compress_size >= RATIO_CHECK_MIN_COMPRESSED:
            ratio = info.file_size / info.compress_size
            if ratio > MAX_COMPRESSION_RATIO:
                problems.append(
                    f"成员 {name!r} 压缩比 {ratio:.0f}:1 异常，疑似压缩炸弹"
                )

    if total_uncompressed > MAX_ZIP_TOTAL_UNCOMPRESSED:
        problems.append(
            f"解压后总大小 {total_uncompressed} 字节，"
            f"超过上限 {MAX_ZIP_TOTAL_UNCOMPRESSED}"
        )

    return problems


def extract_zip_safely(data: bytes, dest_dir: str) -> list[str]:
    """只有通过 analyze_zip 全部检查的压缩包才允许调用本函数。

    即使如此，落盘时仍做二次防护：成员名拍平为 basename，
    并校验最终路径确实位于 dest_dir 之内。
    返回写出的文件路径列表。
    """
    dest_real = os.path.realpath(dest_dir)
    os.makedirs(dest_real, exist_ok=True)
    written: list[str] = []
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            base = os.path.basename(info.filename.replace("\\", "/")) or "unnamed"
            target = os.path.realpath(os.path.join(dest_real, base))
            if os.path.commonpath([dest_real, target]) != dest_real:
                raise ValueError(f"成员 {info.filename!r} 逃逸出目标目录，中止解压")
            # 同名成员去重
            if os.path.exists(target):
                stem, dot, ext = base.rpartition(".")
                target = os.path.join(
                    dest_real, f"{stem or base}_{len(written)}{dot}{ext}" if dot else f"{base}_{len(written)}"
                )
            with zf.open(info) as src, open(target, "wb") as dst:
                while True:
                    chunk = src.read(64 * 1024)
                    if not chunk:
                        break
                    dst.write(chunk)
            written.append(target)
    return written


# ---------------------------------------------------------------- 总入口


def validate_upload(filename: str, data: bytes) -> Verdict:
    """对一次上传做完整校验，返回判定结果。"""
    verdict = Verdict(accepted=False, original_filename=filename)

    # 1. 大小
    if len(data) == 0:
        verdict.reasons.append("文件为空")
        return verdict
    if len(data) > MAX_UPLOAD_SIZE:
        verdict.reasons.append(
            f"文件大小 {len(data)} 字节超过上限 {MAX_UPLOAD_SIZE}"
        )
        return verdict

    # 2. 文件名
    name_problems = check_filename(filename)
    if name_problems:
        verdict.reasons.extend(name_problems)
        return verdict

    # 3. 可执行文件拦截（优先于类型识别，给出更明确的拒绝原因）
    exe = detect_executable(data)
    if exe:
        verdict.reasons.append(f"内容是{exe}，禁止上传")
        return verdict

    # 4. 真实类型识别
    detected = detect_file_type(data)
    verdict.detected_type = detected
    if detected is None:
        verdict.reasons.append("无法识别的文件类型（魔数不在白名单内）")
        return verdict
    if detected not in ALLOWED_TYPES:
        verdict.reasons.append(f"类型 {detected} 不在允许列表中")
        return verdict

    # 5. 扩展名与真实类型一致性
    ext = os.path.splitext(filename)[1].lower()
    claimed = EXT_TO_TYPE.get(ext)
    if claimed is None:
        verdict.reasons.append(f"扩展名 {ext or '(无)'} 不在允许列表中")
        return verdict
    if claimed != detected:
        verdict.reasons.append(
            f"扩展名声称是 {claimed}，但魔数显示真实类型是 {detected}（伪造扩展名）"
        )
        return verdict

    # 6. ZIP 深度检查
    if detected == "zip":
        zip_problems = analyze_zip(data)
        if zip_problems:
            verdict.reasons.extend(zip_problems)
            return verdict

    verdict.accepted = True
    verdict.reasons.append("全部检查通过")
    return verdict
