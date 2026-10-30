"""JSON 寫入在所有平台都產生相同 LF 位元組，原子替換不留暫存，獨佔建立拒絕覆寫。"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from review_core import json_bytes, write_json_atomic, write_json_exclusive

VALUE = {"b": "中文", "a": [1, 2]}


class ReviewCoreWriteTests(unittest.TestCase):
    def test_serialization_is_lf_utf8_with_trailing_newline(self):
        raw = json_bytes(VALUE)
        self.assertNotIn(b"\r", raw)
        self.assertTrue(raw.endswith(b"}\n"))
        self.assertIn("中文".encode("utf-8"), raw)
        self.assertEqual(json.loads(raw), VALUE)
        self.assertLess(json_bytes(VALUE, sort_keys=True).index(b'"a"'),
                        json_bytes(VALUE, sort_keys=True).index(b'"b"'))

    def test_atomic_write_replaces_with_exact_bytes_and_leaves_no_temp(self):
        with tempfile.TemporaryDirectory() as t:
            path = Path(t) / "nested" / "assessment.json"
            write_json_atomic(path, {"old": True})
            write_json_atomic(path, VALUE)
            self.assertEqual(path.read_bytes(), json_bytes(VALUE))
            self.assertEqual([p.name for p in path.parent.iterdir()], ["assessment.json"])

    def test_atomic_write_failure_keeps_original_and_removes_temp(self):
        with tempfile.TemporaryDirectory() as t:
            path = Path(t) / "assessment.json"
            write_json_atomic(path, VALUE)
            with patch("review_core.os.replace", side_effect=OSError("disk")):
                with self.assertRaises(OSError):
                    write_json_atomic(path, {"new": True})
            self.assertEqual(path.read_bytes(), json_bytes(VALUE))
            self.assertEqual([p.name for p in path.parent.iterdir()], ["assessment.json"])

    def test_exclusive_write_refuses_existing_file(self):
        with tempfile.TemporaryDirectory() as t:
            path = Path(t) / "pending.json"
            write_json_exclusive(path, VALUE, sort_keys=True)
            self.assertEqual(path.read_bytes(), json_bytes(VALUE, sort_keys=True))
            with self.assertRaises(FileExistsError):
                write_json_exclusive(path, {"other": True})
            self.assertEqual(path.read_bytes(), json_bytes(VALUE, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
