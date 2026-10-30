"""SHA256SUMS.txt 必須涵蓋全部發布檔，任何新增、刪除或內容變動都要被校驗擋下。"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/lib"))
from package_manifest import MANIFEST, manifest_errors, package_files, render


class PackageManifestTests(unittest.TestCase):
    def _package(self, root: Path) -> None:
        (root / "scripts").mkdir()
        (root / "scripts" / "a.py").write_bytes(b"x = 1\n")
        (root / "SKILL.md").write_bytes(b"# skill\n")
        (root / "scripts" / "__pycache__").mkdir()
        (root / "scripts" / "__pycache__" / "a.cpython-312.pyc").write_bytes(b"\0")
        (root / ".github").mkdir()
        (root / ".github" / "ci.yml").write_bytes(b"on: push\n")
        (root / MANIFEST).write_bytes(render(root).encode("utf-8"))

    def test_fresh_manifest_passes_and_excludes_hidden_and_cache(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            self._package(root)
            self.assertEqual(package_files(root), ["SKILL.md", "scripts/a.py"])
            self.assertEqual(manifest_errors(root), [])

    def test_detects_changed_added_and_removed_files(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            self._package(root)
            (root / "scripts" / "a.py").write_bytes(b"x = 2\n")
            (root / "new.md").write_bytes(b"new\n")
            (root / "SKILL.md").unlink()
            self.assertEqual(manifest_errors(root), [
                f"{MANIFEST} missing entry: new.md",
                f"{MANIFEST} lists absent or excluded file: SKILL.md",
                f"{MANIFEST} hash mismatch: scripts/a.py",
            ])

    def test_missing_or_malformed_manifest_fails(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            self.assertEqual(manifest_errors(root), [f"{MANIFEST} missing"])
            (root / MANIFEST).write_text("oops\n", encoding="utf-8")
            self.assertIn(f"{MANIFEST}:1 malformed line", manifest_errors(root))

    def test_repository_manifest_is_current(self):
        self.assertEqual(manifest_errors(ROOT), [])


if __name__ == "__main__":
    unittest.main()
