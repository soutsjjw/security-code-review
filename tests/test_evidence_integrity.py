"""P5 審查資料封存／交易復原測試：包含中斷寫入、內容竄改與版本衝突。"""
from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import evidence_integrity as ledger
from review_safety import stage, integrate, report_dir, _write


class EvidenceIntegrityTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.report = report_dir(self.root)
        self.snapshot = {
            "schema_version": 1, "git_revision": "test-revision",
            "source_hashes": {"Program.cs": "source-sha"}, "excluded_paths": [],
        }
        _write(self.root / ledger.SNAPSHOT, self.snapshot)
        _write(self.root / ledger.INDEX, {
            "schema_version": 7, "evidence_integrity_version": 1,
            "source_hashes": self.snapshot["source_hashes"],
        })
        self.assessment = {"checks": [
            {"id": "AC-08", "status": "review",
             "execution": {"state": "pending"}, "finding_ids": []}
        ], "findings": [], "file_reviews": []}
        _write(self.report / "assessment.json", self.assessment)

    def seal(self):
        return ledger.initialize(self.root, explicit=True)

    def test_first_seal_idempotent_and_detects_out_of_band_edit(self):
        first = self.seal()
        self.assertTrue(first["initialized"])
        self.assertFalse(self.seal()["initialized"])
        self.assertEqual(ledger.errors(self.root), [])
        self.assessment["findings"] = [{"id": "F-1", "title": "missing authorization"}]
        _write(self.report / "assessment.json", self.assessment)
        self.assertIn("assessment.json", str(ledger.errors(self.root)))
        with self.assertRaisesRegex(ValueError, "不能重新初始化"):
            self.seal()

    def test_missing_manifest_blocks_stage_and_unsealed_old_reviews(self):
        self.assertIn("缺少完整性封存", str(ledger.errors(self.root)))
        draft = self.report / "draft.json"
        _write(draft, {"findings": []})
        with patch("review_safety.snapshot_errors", return_value=[]):
            with self.assertRaisesRegex(ValueError, "缺少完整性封存"):
                stage(self.root, draft)
        self.assessment["checks"][0]["execution"]["state"] = "completed"
        _write(self.report / "assessment.json", self.assessment)
        with self.assertRaisesRegex(ValueError, "不可自動信任"):
            ledger.initialize(self.root)
        self.seal()

    def test_chain_records_multiple_authorized_batches(self):
        self.seal()
        for n in (1, 2, 3):
            a = copy.deepcopy(self.assessment)
            a["checkpoint"] = n
            ledger.commit(self.root, {"assessment.json": a}, event="integrate")
            self.assertEqual(ledger.errors(self.root), [])
        records = [json.loads((self.root / ledger.JOURNAL /
                              f"{i:08d}.json").read_text("utf-8")) for i in range(4)]
        self.assertIsNone(records[0]["previous"])
        self.assertEqual(records[3]["previous"], records[2]["entry_hash"])
        self.assertEqual(json.loads((self.root / ledger.MANIFEST).read_text("utf-8"))
                         ["sequence"], 3)

    def test_chain_missing_corrupt_or_unreferenced_entry_is_rejected(self):
        self.seal()
        ledger.commit(self.root, {"assessment.json": self.assessment}, event="integrate")
        journal = self.root / ledger.JOURNAL / "00000001.json"
        entry = json.loads(journal.read_text("utf-8"))
        entry["event"] = "forged"
        _write(journal, entry)
        self.assertIn("交易日誌", str(ledger.errors(self.root)))
        journal.unlink()
        self.assertIn("缺少序號", str(ledger.errors(self.root)))

    def test_manifest_head_and_snapshot_fingerprint_are_pinned(self):
        self.seal()
        manifest = json.loads((self.root / ledger.MANIFEST).read_text("utf-8"))
        manifest["head"] = "forged"
        _write(self.root / ledger.MANIFEST, manifest)
        self.assertIn("manifest", str(ledger.errors(self.root)))
        manifest["head"] = json.loads((self.root / ledger.JOURNAL / "00000000.json")
                                     .read_text("utf-8"))["entry_hash"]
        _write(self.root / ledger.MANIFEST, manifest)
        updated = copy.deepcopy(self.snapshot)
        updated["source_hashes"]["new.cs"] = "unexpected"
        _write(self.root / ledger.SNAPSHOT, updated)
        self.assertIn("來源快照", str(ledger.errors(self.root)))

    def test_transaction_recovery_after_partial_multifile_write(self):
        self.seal()
        altered = copy.deepcopy(self.assessment)
        altered["checkpoint"] = 99
        actual_write = ledger._write
        def partial_failure(path, value):
            if path.name == "control-verifications.json":
                raise OSError("simulated disk failure")
            return actual_write(path, value)
        with patch("evidence_integrity._write", side_effect=partial_failure):
            with self.assertRaisesRegex(OSError, "simulated disk failure"):
                ledger.commit(self.root, {
                    "assessment.json": altered,
                    "analysis/control-verifications.json": {"AC-08": {"status": "pass"}},
                }, event="integrate")
        self.assertTrue((self.root / ledger.PENDING).is_file())
        self.assertIn("recover-integrity", str(ledger.errors(self.root)))
        result = ledger.recover(self.root)
        self.assertEqual(result["sequence"], 1)
        self.assertEqual(ledger.errors(self.root), [])
        self.assertEqual(json.loads((self.report / "assessment.json").read_text("utf-8")), altered)

    def test_transaction_recovery_after_manifest_written(self):
        self.seal()
        actual_unlink = Path.unlink
        def unlink_failure(path, *args, **kwargs):
            if path.name == "integrity-pending.json":
                raise OSError("simulated power loss")
            return actual_unlink(path, *args, **kwargs)
        with patch("pathlib.Path.unlink", new=unlink_failure):
            with self.assertRaisesRegex(OSError, "simulated power loss"):
                ledger.commit(self.root, {"assessment.json": {**self.assessment, "checked": True}},
                              event="integrate")
        self.assertTrue((self.root / ledger.PENDING).exists())
        self.assertEqual(ledger.recover(self.root)["sequence"], 1)
        self.assertEqual(ledger.errors(self.root), [])

    def test_recovery_rejects_third_party_modifications(self):
        self.seal()
        actual_write = ledger._write
        def crash(path, value):
            if path.name == "assessment.json":
                raise OSError("interruption before file replacement")
            return actual_write(path, value)
        with patch("evidence_integrity._write", side_effect=crash):
            with self.assertRaises(OSError):
                ledger.commit(self.root, {"assessment.json": {"value": 2}}, event="integrate")
        _write(self.report / "assessment.json", {"unauthorized": "third version"})
        with self.assertRaisesRegex(ValueError, "第三種內容修改"):
            ledger.recover(self.root)

    def test_snapshot_refresh_can_reanchor_but_still_records_changes(self):
        self.seal()
        next_snapshot = copy.deepcopy(self.snapshot)
        next_snapshot["source_hashes"]["NewService.cs"] = "new-sha"
        ledger.commit(self.root, {
            "analysis/review-snapshot.json": next_snapshot,
            "analysis/recheck-required.json": {"rule_ids": ["AC-08"]},
            "analysis/rule-closures.json": None,
        }, event="snapshot-refresh", new_snapshot=next_snapshot)
        self.assertEqual(ledger.errors(self.root), [])
        entry = json.loads((self.root / ledger.JOURNAL / "00000001.json").read_text("utf-8"))
        self.assertEqual(entry["event"], "snapshot-refresh")
        self.assertEqual(entry["snapshot_fingerprint"], ledger._fp(next_snapshot))

    def test_stale_stage_head_is_rejected_after_another_transaction(self):
        self.seal()
        draft = self.report / "draft.json"
        _write(draft, {"findings": []})
        with patch("review_safety.snapshot_errors", return_value=[]):
            stage(self.root, draft)
            ledger.commit(self.root, {"assessment.json": {**self.assessment, "changed": True}},
                          event="manual-reconciliation")
            with self.assertRaisesRegex(ValueError, "暫存基礎版本已被其他整合改變"):
                integrate(self.root)

    def test_integrate_persists_finding_without_hash_breakage(self):
        self.seal()
        draft = self.report / "findings.json"
        finding = {"id": "F-1", "title": "Controller authentication bypass",
                   "check_ids": ["AC-08"], "evidence": []}
        _write(draft, {"findings": [finding]})
        with patch("review_safety.snapshot_errors", return_value=[]):
            stage(self.root, draft)
            outcome = integrate(self.root)
        self.assertEqual(outcome["findings"], 1)
        self.assertEqual(ledger.errors(self.root), [])
        result = json.loads((self.report / "assessment.json").read_text("utf-8"))
        self.assertEqual(result["findings"], [finding])
        self.assertFalse(list((self.root / ledger.ANALYSIS / "staged").glob("*.json")))

    def test_new_review_auto_seals_but_existing_review_needs_explicit_seal(self):
        from review_queue import load_rules, initialize as start_review
        self.assertFalse((self.root / ledger.MANIFEST).exists())
        ruleset, rules = load_rules()
        start_review(self.root, self.report, ruleset, rules)
        self.assertFalse((self.root / ledger.MANIFEST).exists())
        (self.report / "assessment.json").unlink()
        start_review(self.root, self.report, ruleset, rules)
        self.assertTrue((self.root / ledger.MANIFEST).exists())
        self.assertEqual(ledger.errors(self.root), [])

    def test_source_refresh_is_an_audited_transaction_and_keeps_findings(self):
        from review_safety import refresh_snapshot
        self.seal()
        with (patch("review_safety.current_hashes",
                    return_value={"Program.cs": "updated-source-hash"}),
              patch("review_safety._revision", return_value="updated-git-revision")):
            refresh_snapshot(self.root)
        self.assertEqual(ledger.errors(self.root), [])
        manifest = json.loads((self.root / ledger.MANIFEST).read_text("utf-8"))
        self.assertEqual(manifest["sequence"], 1)
        journal = json.loads((self.root / ledger.JOURNAL / "00000001.json").read_text("utf-8"))
        self.assertEqual(journal["event"], "snapshot-refresh")
        self.assertEqual(json.loads((self.report / "assessment.json").read_text("utf-8")),
                         self.assessment)

    def test_legacy_index_not_forced_into_unrequested_migration(self):
        _write(self.root / ledger.INDEX, {"schema_version": 6})
        self.assertFalse(ledger.enabled(self.root))
        self.assertEqual(ledger.errors(self.root), [])


if __name__ == "__main__":
    unittest.main()
