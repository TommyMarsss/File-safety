"""security.py 单元测试：魔数识别、文件名清洗、ZIP 炸弹检测。"""
import io
import os
import sys
import unittest
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import samples
import security


class TestMagicDetection(unittest.TestCase):
    def test_valid_png_accepted(self):
        _, data, _ = samples.build_sample("valid-png")
        v = security.validate_upload("photo.png", data)
        self.assertTrue(v.accepted, v.reasons)
        self.assertEqual(v.detected_type, "png")

    def test_valid_zip_accepted(self):
        _, data, _ = samples.build_sample("valid-zip")
        v = security.validate_upload("archive.zip", data)
        self.assertTrue(v.accepted, v.reasons)

    def test_fake_exe_with_png_extension_rejected(self):
        """伪造 .png 后缀的 PE 可执行文件必须被拒绝。"""
        _, data, _ = samples.build_sample("fake-exe-png")
        v = security.validate_upload("vacation.png", data)
        self.assertFalse(v.accepted)
        self.assertTrue(any("可执行文件" in r for r in v.reasons), v.reasons)

    def test_fake_elf_with_jpg_extension_rejected(self):
        _, data, _ = samples.build_sample("fake-elf-jpg")
        v = security.validate_upload("avatar.jpg", data)
        self.assertFalse(v.accepted)
        self.assertTrue(any("ELF" in r for r in v.reasons), v.reasons)

    def test_extension_content_mismatch_rejected(self):
        """内容是 PNG 但扩展名是 .pdf —— 类型不符必须拒绝。"""
        _, png_data, _ = samples.build_sample("valid-png")
        v = security.validate_upload("document.pdf", png_data)
        self.assertFalse(v.accepted)
        self.assertTrue(any("伪造扩展名" in r for r in v.reasons), v.reasons)

    def test_unknown_type_rejected(self):
        v = security.validate_upload("notes.png", b"\x00\x01\x02\x03random")
        self.assertFalse(v.accepted)

    def test_shebang_script_rejected(self):
        v = security.validate_upload("setup.png", b"#!/bin/sh\nrm -rf /\n")
        self.assertFalse(v.accepted)

    def test_empty_file_rejected(self):
        v = security.validate_upload("a.png", b"")
        self.assertFalse(v.accepted)

    def test_oversize_rejected(self):
        v = security.validate_upload(
            "big.png", b"\x89PNG\r\n\x1a\n" + b"x" * security.MAX_UPLOAD_SIZE)
        self.assertFalse(v.accepted)


class TestFilenameTraversal(unittest.TestCase):
    def setUp(self):
        _, self.png, _ = samples.build_sample("valid-png")

    def test_dotdot_filename_rejected(self):
        v = security.validate_upload("../../tmp/evil.png", self.png)
        self.assertFalse(v.accepted)
        self.assertTrue(any("穿越" in r or "分隔符" in r for r in v.reasons))

    def test_absolute_path_rejected(self):
        v = security.validate_upload("/etc/cron.d/backdoor.png", self.png)
        self.assertFalse(v.accepted)

    def test_windows_style_traversal_rejected(self):
        v = security.validate_upload("..\\..\\windows\\system32\\evil.png", self.png)
        self.assertFalse(v.accepted)

    def test_windows_drive_path_rejected(self):
        v = security.validate_upload("C:\\Users\\evil.png", self.png)
        self.assertFalse(v.accepted)

    def test_nul_byte_rejected(self):
        v = security.validate_upload("evil.png\x00.jpg", self.png)
        self.assertFalse(v.accepted)

    def test_hidden_file_rejected(self):
        v = security.validate_upload(".htaccess", self.png)
        self.assertFalse(v.accepted)

    def test_normal_filename_ok(self):
        self.assertEqual(security.check_filename("my photo_2024-01.png"), [])


class TestZipBombs(unittest.TestCase):
    def test_compression_bomb_rejected_before_extraction(self):
        """压缩炸弹必须在元数据分析阶段被拒绝，而不是解压时耗尽资源。"""
        _, data, _ = samples.build_sample("zip-bomb")
        # 压缩后很小，远小于上传上限 —— 若不做元数据检查就会漏过
        self.assertLess(len(data), 1024 * 1024)
        v = security.validate_upload("gift.zip", data)
        self.assertFalse(v.accepted)
        self.assertTrue(
            any("压缩比" in r or "超过" in r for r in v.reasons), v.reasons)

    def test_symlink_zip_rejected(self):
        _, data, _ = samples.build_sample("zip-symlink")
        v = security.validate_upload("backup.zip", data)
        self.assertFalse(v.accepted)
        self.assertTrue(any("符号链接" in r for r in v.reasons), v.reasons)

    def test_zip_slip_rejected(self):
        _, data, _ = samples.build_sample("zip-traversal")
        v = security.validate_upload("update.zip", data)
        self.assertFalse(v.accepted)
        self.assertTrue(any("穿越" in r for r in v.reasons), v.reasons)

    def test_nested_zip_rejected(self):
        buf = io.BytesIO()
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as z:
            z.writestr("a.txt", "hi")
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("inner.zip", inner.getvalue())
        v = security.validate_upload("outer.zip", buf.getvalue())
        self.assertFalse(v.accepted)
        self.assertTrue(any("嵌套" in r for r in v.reasons), v.reasons)

    def test_too_many_entries_rejected(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            for i in range(security.MAX_ZIP_ENTRIES + 1):
                z.writestr(f"f{i}.txt", "x")
        v = security.validate_upload("many.zip", buf.getvalue())
        self.assertFalse(v.accepted)
        self.assertTrue(any("条目数" in r for r in v.reasons), v.reasons)

    def test_corrupt_zip_rejected(self):
        v = security.validate_upload("broken.zip", b"PK\x03\x04" + b"\xff" * 64)
        self.assertFalse(v.accepted)

    def test_safe_extraction_stays_in_dir(self):
        """合法 zip 解压后所有文件必须位于目标目录内。"""
        import tempfile
        _, data, _ = samples.build_sample("valid-zip")
        with tempfile.TemporaryDirectory() as tmp:
            written = security.extract_zip_safely(data, tmp)
            self.assertEqual(len(written), 2)
            for path in written:
                real = os.path.realpath(path)
                self.assertTrue(real.startswith(os.path.realpath(tmp) + os.sep))


if __name__ == "__main__":
    unittest.main()
