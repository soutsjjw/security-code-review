"""R1：分類獨立完整性基礎（Manifest / Journal / SHA256 / 排他鎖）。"""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "scripts"))

from partial_review import _atomic, _category_dir, initialize as init_partial, read_category
from partial_evidence_integrity import (
    HISTORY, JOURNAL, LOCK, MANIFEST, PENDING, STAGED, TRACKED, VERSION,
    IntegrityError, errors, initialize, locked,
)
from review_scope import load_catalog


class CategoryEvidenceIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = load_catalog()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "App.cs").write_text(
            "public sealed class App { public bool Authorized() => false; }\n",
            encoding="utf-8",
        )
        formal = self.root / "reports/security-code-review"
        formal.mkdir(parents=True, exist_ok=True)
        self.formal = {
            name: formal / name for name in (
                "assessment.json", "report.json", "CodeReview_20261024.html"
            )
        }
        for name, path in self.formal.items():
            path.write_text(f"FORMAL/{name}", encoding="utf-8")
        self.formal_before = {name: path.read_bytes() for name, path in self.formal.items()}
        init_partial(self.root, ("AC", "AU"), self.catalog)

    def _folder(self, cat="AC"):
        return _category_dir(self.root, cat)

    def _read(self, relative, cat="AC"):
        return json.loads((self._folder(cat) / relative).read_text(encoding="utf-8"))

    def _formal_unchanged(self):
        self.assertEqual({name: path.read_bytes() for name, path in self.formal.items()},
                         self.formal_before)

    def test_initial_seal_and_repeated_seal_are_idempotent(self):
        outcome = initialize(self.root, "AC")
        self.assertTrue(outcome["initialized"])
        self.assertEqual(outcome["sequence"], 0)
        self.assertEqual(errors(self.root, "AC"), [])
        again = initialize(self.root, "AC")
        self.assertFalse(again["initialized"])
        self.assertEqual(again["head"], outcome["head"])
        manifest = self._read(MANIFEST)
        row = self._read(JOURNAL / "00000000.json")
        self.assertEqual(manifest["schema_version"], VERSION)
        self.assertEqual(manifest["category"], "AC")
        self.assertEqual(manifest["head"], row["entry_hash"])
        self.assertEqual(row["event"], "initial-seal")
        self.assertTrue(set(TRACKED) <= set(row["file_hashes"]))
        self.assertEqual(len(row["file_hashes"]), len(TRACKED))
        self.assertIsNone(row["file_hashes"]["analysis/first-pass-baseline.json"])
        self.assertTrue(row["file_hashes"]["assessment.json"])
        self._formal_unchanged()

    def test_ac_and_au_have_independent_manifests_and_journals(self):
        first = initialize(self.root, "AC")
        self.assertFalse((self._folder("AU") / MANIFEST).exists())
        second = initialize(self.root, "AU")
        self.assertNotEqual(first["head"], second["head"])
        self.assertEqual(errors(self.root, "AC"), [])
        self.assertEqual(errors(self.root, "AU"), [])
        assessment = self._folder("AC") / "assessment.json"
        data = json.loads(assessment.read_text(encoding="utf-8"))
        data["checks"][0]["decision_reason"] = "out-of-band tampering"
        _atomic(assessment, data)
        self.assertTrue(errors(self.root, "AC"))
        self.assertEqual(errors(self.root, "AU"), [])
        self._formal_unchanged()

    def test_untrusted_existing_progress_requires_explicit_manual_seal(self):
        assessment_path = self._folder() / "assessment.json"
        data = read_category(self.root, "AC", self.catalog)
        data["checks"][0]["execution"]["state"] = "completed"
        data["findings"] = [{"id": "F-01", "check_ids": ["AC-01"]}]
        _atomic(assessment_path, data)
        with self.assertRaises(IntegrityError):
            initialize(self.root, "AC")
        self.assertFalse((self._folder() / MANIFEST).exists())
        initialize(self.root, "AC", explicit=True)
        self.assertEqual(errors(self.root, "AC"), [])

    def test_existing_second_pass_evidence_requires_explicit_manual_seal(self):
        folder = self._folder()
        _atomic(folder / "analysis/rule-closures.json", {"AC-01": {"status": "review"}})
        with self.assertRaises(IntegrityError):
            initialize(self.root, "AC")
        initialize(self.root, "AC", explicit=True)
        self.assertEqual(errors(self.root, "AC"), [])

    def test_original_sources_and_git_revision_are_pinned(self):
        initialize(self.root, "AC")
        (self.root / "App.cs").write_text(
            "public sealed class App { public bool Authorized() => true; }\n",
            encoding="utf-8",
        )
        self.assertTrue(errors(self.root, "AC"))
        with self.assertRaises(IntegrityError):
            initialize(self.root, "AC")

    def test_manifest_and_journal_tampering_are_detected(self):
        initialize(self.root, "AC")
        manifest_path = self._folder() / MANIFEST
        data = self._read(MANIFEST)
        data["head"] = "0" * 64
        _atomic(manifest_path, data)
        self.assertIn("head", " ".join(errors(self.root, "AC")))
        with self.assertRaises(IntegrityError):
            initialize(self.root, "AC")

        original = self._read(JOURNAL / "00000000.json")
        # Restore manifest only for second negative scenario.
        data["head"] = original["entry_hash"]
        _atomic(manifest_path, data)
        original["file_hashes"]["assessment.json"] = "1" * 64
        _atomic(self._folder() / JOURNAL / "00000000.json", original)
        self.assertIn("日誌", " ".join(errors(self.root, "AC")))

    def test_unknown_or_missing_journal_entry_fails_closed(self):
        initialize(self.root, "AC")
        extra = self._folder() / JOURNAL / "00000001.json"
        _atomic(extra, {"unexpected": True})
        self.assertTrue(errors(self.root, "AC"))
        extra.unlink()
        (self._folder() / JOURNAL / "00000000.json").unlink()
        self.assertTrue(errors(self.root, "AC"))

    def test_unfinished_transaction_blocks_validation_and_initialization(self):
        initialize(self.root, "AC")
        pending_path = self._folder() / PENDING
        _atomic(pending_path, {"transaction": "incomplete"})
        self.assertIn("未完成", " ".join(errors(self.root, "AC")))
        with self.assertRaises(IntegrityError):
            initialize(self.root, "AC")
        self.assertTrue(pending_path.is_file())

    def test_unsealed_dangling_journal_cannot_be_resealed(self):
        folder = self._folder()
        _atomic(folder / JOURNAL / "00000000.json", {"corrupted": True})
        with self.assertRaises(IntegrityError):
            initialize(self.root, "AC", explicit=True)
        self.assertFalse((folder / MANIFEST).exists())

    def test_unintegrated_staged_payload_cannot_be_sealed(self):
        _atomic(self._folder() / STAGED, {"payload": {"checks": []}})
        with self.assertRaises(IntegrityError):
            initialize(self.root, "AC", explicit=True)
        self.assertFalse((self._folder() / MANIFEST).exists())

    def test_lock_is_exclusive_and_does_not_disappear_on_conflict(self):
        with locked(self.root, "AC"):
            lockfile = self._folder() / LOCK
            self.assertTrue(lockfile.is_file())
            with self.assertRaises(IntegrityError):
                initialize(self.root, "AC")
            with self.assertRaises(IntegrityError):
                with locked(self.root, "AC"):
                    pass
            self.assertTrue(lockfile.is_file())
            # Different categories can acquire their own locks.
            with locked(self.root, "AU"):
                self.assertTrue((self._folder("AU") / LOCK).exists())
            self.assertFalse((self._folder("AU") / LOCK).exists())
        self.assertFalse((self._folder() / LOCK).exists())

    def test_existing_lock_must_not_be_automatically_removed(self):
        path = self._folder() / LOCK
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("pid=someone-else\n", encoding="utf-8")
        with self.assertRaises(IntegrityError):
            initialize(self.root, "AC")
        self.assertEqual(path.read_text("utf-8"), "pid=someone-else\n")

    def test_second_pass_history_is_part_of_integrity_chain(self):
        history = self._folder() / HISTORY
        history.mkdir(parents=True)
        name = "a" * 32 + ".json"
        _atomic(history / name, {"AC-01": "original pass"})
        with self.assertRaises(IntegrityError):
            initialize(self.root, "AC")
        initialize(self.root, "AC", explicit=True)
        self.assertEqual(errors(self.root, "AC"), [])
        _atomic(history / name, {"AC-01": "tampered"})
        self.assertTrue(errors(self.root, "AC"))

    def test_new_history_file_after_seal_is_not_silently_trusted(self):
        initialize(self.root, "AC")
        history = self._folder() / HISTORY
        _atomic(history / ("b" * 32 + ".json"), {"unexpected": True})
        self.assertIn("清單變更", " ".join(errors(self.root, "AC")))

    def test_unexpected_history_name_fails_closed(self):
        folder = self._folder() / HISTORY
        folder.mkdir(parents=True)
        _atomic(folder / "untrusted.json", {"fake": True})
        with self.assertRaises(IntegrityError):
            initialize(self.root, "AC", explicit=True)
        self.assertTrue(errors(self.root, "AC"))

    @unittest.skipIf(not hasattr(os, "symlink"), "Platform has no symlink support")
    def test_symlink_to_formal_assessment_cannot_be_sealed(self):
        formal = self.formal["assessment.json"]
        entry = self._folder() / "analysis/rule-closures.json"
        try:
            entry.symlink_to(formal)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(str(exc))
        with self.assertRaises(IntegrityError):
            initialize(self.root, "AC", explicit=True)
        self._formal_unchanged()


if __name__ == "__main__":
    unittest.main()
