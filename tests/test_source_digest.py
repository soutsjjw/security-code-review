"""逐檔 SHA256 的跨平台行為：CRLF／LF、BOM 差異不應使審查失效，真正內容異動仍須偵測。"""
import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_ROOT / 'scripts'))
from review_fixture import make_file_review
from source_coverage import build_source_coverage
from source_reader import canonical_bytes, digest_matches, source_digest

LF = "var a = 1;\nvar b = 2;\n".encode("utf-8")
CRLF = LF.replace(b"\n", b"\r\n")
BOM = b"\xef\xbb\xbf"


class DigestFunctionTests(unittest.TestCase):
    def test_canonical_digest_ignores_eol_and_bom(self):
        self.assertEqual(source_digest(LF), source_digest(CRLF))
        self.assertEqual(source_digest(LF), source_digest(BOM + CRLF))

    def test_content_change_alters_digest(self):
        self.assertNotEqual(source_digest(LF), source_digest(LF.replace(b"1", b"3")))
        self.assertNotEqual(source_digest(LF), source_digest(LF.replace(b"var b", b"var  b")))

    def test_only_crlf_is_normalized(self):
        self.assertEqual(canonical_bytes(b"a\r\nb\rc\n"), b"a\nb\rc\n")

    def test_legacy_raw_hashes_are_still_accepted_across_checkouts(self):
        # 舊版在 Windows 以 CRLF 位元組計算；Linux 檢出為 LF 時仍須通過。
        legacy_windows = hashlib.sha256(CRLF).hexdigest()
        legacy_bom_windows = hashlib.sha256(BOM + CRLF).hexdigest()
        for raw in (LF, CRLF, BOM + LF):
            self.assertTrue(digest_matches(legacy_windows, raw))
            self.assertTrue(digest_matches(legacy_bom_windows, raw))
            self.assertTrue(digest_matches(source_digest(LF), raw))

    def test_invalid_or_foreign_digest_rejected(self):
        self.assertFalse(digest_matches(None, LF))
        self.assertFalse(digest_matches("0" * 64, LF))
        self.assertFalse(digest_matches(hashlib.sha256(LF.replace(b"1", b"9")).hexdigest(), LF))


class IntegrationTests(unittest.TestCase):
    def _coverage(self, stored_digest, on_disk):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Auth.cs").write_bytes(LF)
            row = make_file_review(root, "Auth.cs", ("AC-01",))
            row["sha256"] = stored_digest
            (root / "Auth.cs").write_bytes(on_disk)
            assessment = {"checks": [{"id": "AC-01", "status": "review",
                                      "execution": {"state": "completed", "inspected_paths": ["Auth.cs"]}}],
                          "file_reviews": [row]}
            return build_source_coverage(assessment, root)

    def test_windows_hash_verifies_on_linux_checkout(self):
        coverage = self._coverage(hashlib.sha256(CRLF).hexdigest(), LF)
        self.assertNotIn("sha256", str(coverage["review_integrity_errors"]))

    def test_canonical_hash_verifies_for_either_checkout(self):
        for disk in (LF, CRLF, BOM + CRLF):
            coverage = self._coverage(source_digest(LF), disk)
            self.assertNotIn("sha256", str(coverage["review_integrity_errors"]))

    def test_real_modification_still_rejected(self):
        coverage = self._coverage(source_digest(LF), LF.replace(b"1", b"3"))
        self.assertIn("sha256", str(coverage["review_integrity_errors"]))


class CliTests(unittest.TestCase):
    def test_digest_flag_prints_canonical_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "A.cs").write_bytes(BOM + CRLF)
            run = subprocess.run([sys.executable, str(SKILL_ROOT / "scripts/source_reader.py"),
                                  "--source-root", str(root), "--path", "A.cs", "--digest"],
                                 capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(run.stdout.split()[0], source_digest(LF))
            self.assertIn("A.cs", run.stdout)


if __name__ == "__main__":
    unittest.main()
