"""P0: L3 降級與 analysis 臨時腳本的實際稽核。"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/lib"))
import review_log
import execution_boundary as boundary
import evidence_integrity as ledger
from legacy_script_archive import archive as archive_scripts

class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        review_log.start(self.root)
    def test_untrusted_inventory_is_never_L2(self):
        self.assertEqual(boundary.inventory(self.root)["boundary_level"], "L3")
        self.assertFalse(boundary.inventory(self.root)["trusted_inventory_available"])
    def test_existing_legacy_script_is_not_auto_deleted(self):
        folder = self.root / "reports/security-code-review/analysis"
        folder.mkdir(parents=True)
        old = folder / "repair_old.py"
        old.write_text("print('old')\n", encoding="utf-8")
        baseline = boundary.begin(self.root)
        self.assertIn("repair_old.py", baseline["scripts"])
        self.assertFalse(baseline["legacy_cleanup_allowed"])
        self.assertTrue(old.exists())
        self.assertTrue(boundary.inspect(self.root, batch_id="preflight")["clean"])
    def test_new_script_rejected_without_modifying_existing_assessment(self):
        folder = self.root / "reports/security-code-review/analysis"
        folder.mkdir(parents=True)
        assessment = folder.parent / "assessment.json"
        assessment.write_text('{"findings":[{"id":"F-1"}]}', encoding="utf-8")
        boundary.begin(self.root)
        (folder / "generated.py").write_text("print(1)\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "拒絕整合"):
            boundary.require_clean(self.root, batch_id="sample")
        self.assertEqual(json.loads(assessment.read_text("utf-8"))["findings"][0]["id"], "F-1")
        scan = boundary.inspect(self.root, batch_id="sample")
        self.assertFalse(scan["clean"])
    def test_baseline_cannot_be_overwritten(self):
        boundary.begin(self.root)
        with self.assertRaises(ValueError):
            boundary.begin(self.root)

class JournalBoundaryTests(unittest.TestCase):
    def test_optional_v1_attestation_and_old_chain_compatible(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            snapshot = {"schema_version": 1, "git_revision": "test",
                        "source_hashes": {"Api.cs": "abc"}, "excluded_paths": []}
            path = root / ledger.SNAPSHOT
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(snapshot), encoding="utf-8")
            index = root / ledger.INDEX
            index.write_text(json.dumps({"schema_version": 7,
                                         "evidence_integrity_version": 1,
                                         "source_hashes": snapshot["source_hashes"]}), encoding="utf-8")
            assessment = root / ledger.RELATIVE / "assessment.json"
            assessment.write_text('{"checks":[],"findings":[],"file_reviews":[]}', encoding="utf-8")
            ledger.initialize(root, explicit=True)
            att = {"schema_version": 1, "run_id": "run", "batch_id": "batch",
                   "boundary_level": "L3", "inventory_sha256": "a"*64,
                   "summary_sha256": "b"*64}
            ledger.commit(root, {}, event="integrate", boundary_attestation=att)
            self.assertEqual(ledger.errors(root), [])
            entry = json.loads((root / ledger.JOURNAL / "00000001.json").read_text("utf-8"))
            self.assertEqual(entry["boundary_attestation"], att)
            self.assertNotIn("boundary_attestation", json.loads(
                (root / ledger.JOURNAL / "00000000.json").read_text("utf-8")))
            with self.assertRaises(ValueError):
                ledger.commit(root, {}, event="integrate",
                              boundary_attestation={**att, "summary_sha256": "bad"})
            script = root / ledger.RELATIVE / "analysis/legacy_repair.py"
            script.write_text("print('old')", encoding="utf-8")
            receipt = archive_scripts(root)
            self.assertFalse(receipt["allow_cleanup"])
            self.assertTrue(script.exists())
            self.assertEqual(ledger.errors(root), [])
            latest = json.loads((root / ledger.JOURNAL / "00000002.json").read_text("utf-8"))
            self.assertEqual(latest["event"], "legacy-script-archive")
            self.assertEqual(latest["archive_attestation"], receipt)
            archived = root / ledger.RELATIVE / "archive/legacy-scripts"
            next(archived.iterdir()).write_text("tampered", encoding="utf-8")
            self.assertIn("封存", str(ledger.errors(root)))

if __name__ == "__main__":
    unittest.main()
