"""P0～P4：內容備份、原始 bytes 復原、無備份重新取證與修訂授權守門。"""
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
from review_evidence_recovery import archive_for_recheck, plan
from review_safety import _write, integrate, report_dir, stage


class DurableEvidenceRecoveryTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.target = Path(temp.name)
        self.report = report_dir(self.target)
        self.snapshot = {"schema_version": 1, "git_revision": "fixed-test",
                         "source_hashes": {"Handler.cs": "pinned-source-hash"},
                         "excluded_paths": []}
        _write(self.target / ledger.SNAPSHOT, self.snapshot)
        _write(self.target / ledger.INDEX, {"schema_version": 10, "evidence_integrity_version": 1})
        self.findings = [
            {"id": f"F-{i:02d}", "title": f"真實待核對弱點 {i}",
             "check_ids": ["AC-08"], "evidence": [{"path": "Handler.cs", "line_start": 1}]}
            for i in range(10)
        ]
        self.assessment = {"checks": [{"id": "AC-08", "status": "fail",
                                       "finding_ids": [f["id"] for f in self.findings],
                                       "execution": {"state": "completed", "methods": ["source"]}}],
                           "file_reviews": [], "findings": self.findings}
        _write(self.report / "assessment.json", self.assessment)
        _write(self.report / "analysis/rule-closures.json", {
            "AC-08": {"status": "fail", "summary": "實際測試用閉包（不是正式掃描）"}
        })
        ledger.initialize(self.target, explicit=True)

    def closure_path(self):
        return self.report / "analysis/rule-closures.json"

    def backup(self, path):
        return ledger._backup_path(self.target, ledger.digest(path.read_bytes()))

    def test_initial_seal_and_commits_deduplicate_full_evidence(self):
        assessment_path = self.report / "assessment.json"
        old_sha = ledger.digest(assessment_path.read_bytes())
        old_backup = self.backup(assessment_path)
        self.assertTrue(old_backup.is_file())
        self.assertEqual(old_backup.read_bytes(), assessment_path.read_bytes())
        self.assertTrue(self.backup(self.closure_path()).is_file())
        next_assessment = copy.deepcopy(self.assessment)
        next_assessment["reviewed"] = 1
        ledger.commit(self.target, {"assessment.json": next_assessment}, event="integrate")
        self.assertTrue(old_backup.is_file())
        self.assertEqual(ledger.digest(old_backup.read_bytes()), old_sha)
        self.assertTrue(self.backup(assessment_path).is_file())
        record = ledger._read(self.target / ledger.JOURNAL / "00000001.json")
        self.assertEqual(record["backup_mode"], ledger.BACKUP_MODE)
        self.assertEqual(ledger.errors(self.target), [])
        self.assertTrue(ledger.backup_status(self.target)["ready"])

    def test_deleted_rule_closure_restores_exact_bytes_and_preserves_ten_findings(self):
        before = self.closure_path().read_bytes()
        old_manifest = ledger._read(self.target / ledger.MANIFEST)
        self.closure_path().unlink()
        self.assertIn("rule-closures.json", str(ledger.errors(self.target)))
        diagnosis = plan(self.target)
        self.assertTrue(diagnosis["can_restore_from_backup"])
        self.assertEqual(diagnosis["preserved_finding_count"], 10)
        result = ledger.restore_backups(self.target)
        self.assertEqual(result["restored_paths"], ["analysis/rule-closures.json"])
        self.assertEqual(self.closure_path().read_bytes(), before)
        self.assertEqual(ledger.errors(self.target), [])
        self.assertEqual(ledger._read(self.report / "assessment.json")["findings"], self.findings)
        self.assertEqual(ledger._read(self.target / ledger.MANIFEST)["sequence"],
                         old_manifest["sequence"] + 1)
        self.assertEqual(ledger._read(self.target / ledger.JOURNAL / "00000001.json")["event"],
                         "backup-restore")

    def test_modified_evidence_requires_explicit_replacement(self):
        self.closure_path().write_text('{"tampered": true}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "allow-damaged-replacement"):
            ledger.restore_backups(self.target)
        result = ledger.restore_backups(self.target, allow_replace=True)
        self.assertIn("analysis/rule-closures.json", result["restored_paths"])
        self.assertEqual(ledger.errors(self.target), [])

    def test_corrupt_backup_cannot_be_used_to_restore(self):
        location = self.backup(self.closure_path())
        location.write_text("false", encoding="utf-8")
        self.closure_path().unlink()
        with self.assertRaisesRegex(ValueError, "SHA256"):
            ledger.restore_backups(self.target)
        self.assertFalse(self.closure_path().exists())
        self.assertFalse(plan(self.target)["can_restore_from_backup"])

    def test_missing_backup_with_intact_sources_can_be_checkpointed(self):
        self.backup(self.closure_path()).unlink()
        self.assertIn("持久化備份不合格", str(ledger.errors(self.target)))
        self.assertEqual(plan(self.target)["next_action"], "checkpoint")
        with self.assertRaisesRegex(ValueError, "請先執行 --checkpoint"):
            archive_for_recheck(self.target, acknowledged=True)
        result = ledger.repair_backups(self.target)
        self.assertEqual(result["sequence"], 1)
        self.assertEqual(ledger.errors(self.target), [])
        self.assertTrue(ledger.backup_status(self.target)["ready"])

    def test_tampered_journal_rejects_restore_even_if_backup_is_valid(self):
        journal = self.target / ledger.JOURNAL / "00000000.json"
        row = ledger._read(journal)
        row["event"] = "changed"
        _write(journal, row)
        self.closure_path().unlink()
        with self.assertRaisesRegex(ValueError, "交易鏈不可信"):
            ledger.restore_backups(self.target)

    def test_pending_transaction_uses_existing_recovery_path(self):
        self.closure_path().unlink()
        _write(self.target / ledger.PENDING, {"untrusted": True})
        with self.assertRaisesRegex(ValueError, "完整性交易鏈不可信"):
            ledger.restore_backups(self.target)
        with self.assertRaisesRegex(ValueError, "待復原交易"):
            archive_for_recheck(self.target, acknowledged=True)

    def test_irrecoverable_archive_requires_ack_and_never_relabels_findings_confirmed(self):
        self.backup(self.closure_path()).unlink()
        self.closure_path().unlink()
        with self.assertRaisesRegex(ValueError, "acknowledge-evidence-loss"):
            archive_for_recheck(self.target)
        result = archive_for_recheck(self.target, acknowledged=True)
        archived = Path(result["archived_at"])
        self.assertTrue((archived / "assessment.json").is_file())
        self.assertEqual(ledger._read(archived / "assessment.json")["findings"], self.findings)
        self.assertEqual(result["retained_finding_count"], 10)
        marker = ledger._read(self.report / "analysis/prior-findings-unverified.json")
        self.assertEqual(marker["status"], "unverified-prior-evidence")
        self.assertEqual(marker["findings"], self.findings)
        self.assertFalse((self.report / "assessment.json").exists())
        self.assertTrue((archived / "analysis/integrity-manifest.json").is_file())
        self.assertTrue((archived / "analysis/integrity-journal/00000000.json").is_file())

    def test_no_disaster_restart_while_trusted_backup_can_restore(self):
        self.closure_path().unlink()
        with self.assertRaisesRegex(ValueError, "可信備份仍可恢復"):
            archive_for_recheck(self.target, acknowledged=True)
        self.assertTrue((self.report / "assessment.json").is_file())

    def test_checkpoint_cannot_reset_untrusted_chain(self):
        self.closure_path().unlink()
        with self.assertRaisesRegex(ValueError, "正式證據"):
            ledger.repair_backups(self.target)
        self.assertFalse((self.target / ledger.JOURNAL / "00000001.json").exists())

    def test_scoped_completed_revision_needs_flag_and_preserves_findings(self):
        amended = copy.deepcopy(self.assessment["checks"][0])
        amended["decision_reason"] = "重新閱讀原始碼後補充具體的控制失效原因；維持 fail 與既有 Finding。"
        draft = self.report / "amended-completed.json"
        _write(draft, {"checks": [amended]})
        with patch("review_safety.snapshot_errors", return_value=[]):
            stage(self.target, draft)
            with self.assertRaisesRegex(ValueError, "明確人工允許修訂"):
                integrate(self.target)
            outcome = integrate(self.target, allow_revision=True)
        self.assertEqual(outcome["checks"], 1)
        current = ledger._read(self.report / "assessment.json")
        self.assertEqual(current["findings"], self.findings)
        self.assertEqual(current["checks"][0]["status"], "fail")
        self.assertEqual(current["checks"][0]["decision_reason"], amended["decision_reason"])
        self.assertEqual(ledger.errors(self.target), [])

    def test_revision_permission_does_not_imply_finding_permission(self):
        # /goal 的預先授權只涵蓋 --allow-revision，仍不能以此修改既有 Finding。
        finding = copy.deepcopy(self.findings[0])
        finding["title"] = "新標題（需另外授權）"
        draft = self.report / "finding-revision.json"
        _write(draft, {"findings": [finding], "finding_revisions": {"F-00": {
            "reason": "重新核對真實控制責任及安全判定依據，因原始標題過大而建議修改，但本案例未授權改動 Finding。",
            "reviewer": "test-reviewer",
        }}})
        with patch("review_safety.snapshot_errors", return_value=[]):
            stage(self.target, draft)
            with self.assertRaisesRegex(ValueError, "須明確授權"):
                integrate(self.target, allow_revision=True)
        self.assertEqual(ledger.errors(self.target), [])


if __name__ == "__main__":
    unittest.main()
