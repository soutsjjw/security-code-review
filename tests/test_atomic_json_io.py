"""Windows 存取／分享衝突下的原子 JSON 寫入與正式 Manifest 回歸測試。"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import atomic_json_io as atomic
import evidence_integrity as ledger
from review_safety import _write as formal_write


def windows_error(code: int) -> PermissionError:
    error = PermissionError(13, f"WinError {code}: access temporarily denied")
    error.winerror = code
    return error


class AtomicJsonWindowsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.dir = Path(temporary.name)
        self.manifest = self.dir / "integrity-manifest.json"
        self.manifest.write_text('{"head":"old"}\n', encoding="utf-8")

    def assert_no_leftover(self):
        self.assertEqual(list(self.dir.glob(".integrity-manifest.json.*.tmp")), [])

    def test_transient_winerror_5_retries_and_preserves_json(self):
        original = atomic._replace
        attempts = []
        def intermittently_locked(source, destination):
            attempts.append(source)
            if len(attempts) <= 2:
                raise windows_error(5)
            return original(source, destination)

        with patch("atomic_json_io._replace", side_effect=intermittently_locked), \
             patch("atomic_json_io.time.sleep") as sleep:
            formal_write(self.manifest, {"head": "trusted", "sequence": 3})
        self.assertEqual(len(attempts), 3)
        self.assertEqual(len(set(attempts)), 1)
        self.assertEqual(sleep.call_count, 2)
        self.assertEqual(json.loads(self.manifest.read_text("utf-8")),
                         {"head": "trusted", "sequence": 3})
        self.assert_no_leftover()

    def test_winerror_32_retries_for_evidence_integrity_writer(self):
        original = atomic._replace
        calls = 0
        def sharing_violation(source, dest):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise windows_error(32)
            return original(source, dest)
        with patch("atomic_json_io._replace", side_effect=sharing_violation), \
             patch("atomic_json_io.time.sleep"):
            ledger._write(self.manifest, {"head": "journal-head"})
        self.assertEqual(calls, 2)
        self.assertEqual(json.loads(self.manifest.read_text("utf-8")),
                         {"head": "journal-head"})
        self.assert_no_leftover()

    def test_permanent_winerror_5_raises_without_changing_original(self):
        before = self.manifest.read_bytes()
        with patch("atomic_json_io._replace", side_effect=windows_error(5)) as replace, \
             patch("atomic_json_io.time.sleep") as sleep:
            with self.assertRaises(PermissionError):
                formal_write(self.manifest, {"head": "untrusted"})
        self.assertEqual(replace.call_count, len(atomic.REPLACE_DELAYS) + 1)
        self.assertEqual(sleep.call_count, len(atomic.REPLACE_DELAYS))
        self.assertEqual(self.manifest.read_bytes(), before)
        self.assert_no_leftover()

    def test_non_windows_permission_error_not_silently_retried(self):
        before = self.manifest.read_bytes()
        with patch("atomic_json_io._replace", side_effect=PermissionError("denied")) as replace, \
             patch("atomic_json_io.time.sleep") as sleep:
            with self.assertRaises(PermissionError):
                ledger._write(self.manifest, {"head": "anything"})
        replace.assert_called_once()
        sleep.assert_not_called()
        self.assertEqual(self.manifest.read_bytes(), before)
        self.assert_no_leftover()

    def test_unique_temporary_files_and_existing_destination_can_be_replaced(self):
        originals = []
        actual = atomic._replace
        def capture(source, target):
            originals.append(source)
            return actual(source, target)
        with patch("atomic_json_io._replace", side_effect=capture):
            formal_write(self.manifest, {"head": "first"})
            ledger._write(self.manifest, {"head": "second"})
        self.assertEqual(len(originals), 2)
        self.assertNotEqual(originals[0], originals[1])
        self.assertNotIn(self.manifest, originals)
        self.assertEqual(self.manifest.read_text("utf-8"), '{\n  "head": "second"\n}\n')
        self.assert_no_leftover()


if __name__ == "__main__":
    unittest.main()
