"""SHA256 差異分類不會覆寫審查紀錄，也不會把真實異動當 BOM／CRLF。"""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/lib"))
from hash_audit import audit_hashes

LF = b"a = 1;\nb = 2;\n"
CRLF = LF.replace(b"\n", b"\r\n")


class HashAuditTests(unittest.TestCase):
    def test_classifies_all_mismatches_without_changing_source(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "same.cs").write_bytes(LF)
            (root / "changed.cs").write_bytes(b"a = 3;\n")
            (root / "plain.cs").write_bytes(LF)
            assessment = {"file_reviews": [
                {"path": "same.cs", "sha256": hashlib.sha256(CRLF).hexdigest()},
                {"path": "changed.cs", "sha256": hashlib.sha256(LF).hexdigest()},
                {"path": "plain.cs", "sha256": hashlib.sha256(LF).hexdigest()},
                {"path": "missing.cs", "sha256": hashlib.sha256(LF).hexdigest()},
                {"path": "invalid.cs", "sha256": "oops"},
            ]}
            report = audit_hashes(assessment, root)
            self.assertEqual(report["summary"], {
                "total": 5, "raw_match": 1, "compatible_match": 1,
                "content_mismatch": 1, "invalid_digest": 1, "unreadable": 1,
            })
            self.assertEqual(len(report["issues"]), 4)
            mismatch = next(x for x in report["issues"] if x["path"] == "changed.cs")
            self.assertNotEqual(mismatch["stored_sha256"], mismatch["current_canonical_sha256"])
            self.assertEqual((root / "changed.cs").read_bytes(), b"a = 3;\n")

    def test_cli_returns_nonzero_for_actual_mismatch(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "A.cs").write_bytes(b"modified")
            assessment = root / "assessment.json"
            assessment.write_text(json.dumps({"file_reviews": [
                {"path": "A.cs", "sha256": hashlib.sha256(b"original").hexdigest()}
            ]}), encoding="utf-8")
            p = subprocess.run([sys.executable, str(ROOT / "scripts/hash_audit.py"),
                                "--target", str(root), "--assessment", str(assessment)],
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, 1, p.stderr)
            self.assertEqual(json.loads(p.stdout)["summary"]["content_mismatch"], 1)


if __name__ == "__main__":
    unittest.main()
