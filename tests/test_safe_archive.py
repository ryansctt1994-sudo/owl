"""Dependency-free ZIP extraction regression tests."""
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from owl.utils.safe_archive import safe_extract_zip


class ArchiveSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / "sample.zip"
        self.cache = self.root / "cache"

    def build(self, members):
        with zipfile.ZipFile(self.archive, "w") as z:
            for name, data in members:
                z.writestr(name, data)

    def test_nested_valid_archive(self):
        self.build([("a/", b""), ("a/note.txt", b"hello")])
        outputs = safe_extract_zip(str(self.archive), str(self.cache))
        self.assertEqual(len(outputs), 1)
        self.assertEqual(Path(outputs[0]).read_bytes(), b"hello")

    def test_dotdot_traversal_rejected_before_any_write(self):
        self.build([("ok.txt", b"fine"), ("../escape.txt", b"danger")])
        with self.assertRaisesRegex(ValueError, "Unsafe ZIP"):
            safe_extract_zip(str(self.archive), str(self.cache))
        self.assertFalse((self.cache / "sample").exists())
        self.assertFalse((self.root / "escape.txt").exists())

    def test_windows_and_absolute_paths_rejected(self):
        for member in ("..\\escape.txt", "/tmp/escape.txt", "C:\\temp\\escape.txt"):
            with self.subTest(member=member):
                self.build([(member, b"bad")])
                with self.assertRaisesRegex(ValueError, "Unsafe ZIP"):
                    safe_extract_zip(str(self.archive), str(self.cache))

    def test_symlinks_rejected(self):
        info = zipfile.ZipInfo("unsafe-link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.build([(info, b"/outside")])
        with self.assertRaisesRegex(ValueError, "symlink"):
            safe_extract_zip(str(self.archive), str(self.cache))

    def test_zip_bomb_limit_rejected(self):
        self.build([("payload.bin", b"X" * 64)])
        with patch("owl.utils.safe_archive.MAX_BYTES", 16):
            with self.assertRaisesRegex(ValueError, "size exceeds"):
                safe_extract_zip(str(self.archive), str(self.cache))
        self.assertFalse((self.cache / "sample").exists())

    def test_existing_file_is_never_overwritten(self):
        self.build([("note.txt", b"new")])
        dest = self.cache / "sample"
        dest.mkdir(parents=True)
        (dest / "note.txt").write_bytes(b"original")
        with self.assertRaises(FileExistsError):
            safe_extract_zip(str(self.archive), str(self.cache))
        self.assertEqual((dest / "note.txt").read_bytes(), b"original")

    def test_duplicate_member_rejected(self):
        self.build([("same.txt", b"one"), ("same.txt", b"two")])
        with self.assertRaisesRegex(ValueError, "Duplicate ZIP"):
            safe_extract_zip(str(self.archive), str(self.cache))


if __name__ == "__main__":
    unittest.main()
