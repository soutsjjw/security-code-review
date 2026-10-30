"""Regression tests for scoped, fail-closed source snapshot revalidation."""
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

from snapshot_impact import affected_rules, source_delta
from review_blockers import summarize
from review_safety import _write, integrate, refresh_snapshot, stage
from review_snapshot import _read, report_dir, snapshot_errors


class ImpactTests(unittest.TestCase):
    def setUp(self):
        self.scopes = {"AC-01": "cross_file", "AU-09": "cross_file",
                       "DP-01": "project", "CR-02": "local"}
        self.old = {"A.cs": "sha-a", "B.cs": "sha-b", "C.cs": "sha-c"}
        self.new = {**self.old, "A.cs": "sha-a2"}
        self.index = {"source_hashes": self.old,
                      "rule_candidates": {
                          "A.cs": [{"rule_id": "AC-01"}],
                          "B.cs": [{"rule_id": "AU-09"}],
                          "C.cs": [{"rule_id": "CR-02"}]},
                      "typed_relationships": [],
                      "cross_file_call_hints": {}}
        self.assessment = {"checks": [
            {"id": rid, "execution": {"inspected_paths": []}}
            for rid in self.scopes], "file_reviews": []}

    def impact(self, new=None, index=None, assessment=None, closures=None, fresh=None):
        if fresh is None:
            fresh = {"A.cs": [{"rule_id": "AC-01"}]}
        return affected_rules(self.old, new if new is not None else self.new,
                              index if index is not None else self.index,
                              assessment if assessment is not None else self.assessment,
                              closures if closures is not None else {}, self.scopes,
                              current_candidates=fresh)

    def test_git_only_delta_never_invalidates_source_rules(self):
        self.assertEqual(source_delta(self.old, dict(self.old))["modified"], [])
        self.assertEqual(self.impact(new=dict(self.old))["rule_ids"], [])

    def test_tracked_source_limits_scope_but_includes_project_controls(self):
        result = self.impact()
        self.assertFalse(result["full_recheck"])
        self.assertEqual(result["rule_ids"], ["AC-01", "DP-01"])
        self.assertEqual(result["changed_paths"], ["A.cs"])

    def test_cross_file_graph_and_closure_expand_scope(self):
        self.index["typed_relationships"] = [{"id": "edge-1", "source": "A.cs",
                                                "target": "B.cs"}]
        result = self.impact()
        self.assertIn("AU-09", result["rule_ids"])
        self.assertNotIn("CR-02", result["rule_ids"])

    def test_changed_file_has_no_authoritative_owner_fails_closed(self):
        self.index["rule_candidates"]["A.cs"] = []
        self.assertTrue(self.impact(fresh={"A.cs": []})["full_recheck"])

    def test_newly_introduced_control_candidate_is_also_rechecked(self):
        result = self.impact(fresh={"A.cs": [{"rule_id": "CR-02"}]})
        self.assertEqual(result["rule_ids"], ["AC-01", "CR-02", "DP-01"])

    def test_added_removed_and_configuration_sources_fail_closed(self):
        self.assertTrue(self.impact(new={**self.old, "D.cs": "new"})["full_recheck"])
        removed = {k: v for k, v in self.old.items() if k != "A.cs"}
        self.assertTrue(self.impact(new=removed)["full_recheck"])
        old_config = {**self.old, "appsettings.json": "v1"}
        new_config = {**old_config, "appsettings.json": "v2"}
        self.assertTrue(affected_rules(old_config, new_config, self.index,
                                       self.assessment, {}, self.scopes)["full_recheck"])

    def test_stale_or_malformed_index_fails_closed(self):
        stale = {**self.index, "source_hashes": {"A.cs": "wrong"}}
        self.assertTrue(self.impact(index=stale)["full_recheck"])
        malformed = {**self.index, "typed_relationships": [{"source": None, "target": "A.cs"}]}
        self.assertTrue(self.impact(index=malformed)["full_recheck"])


class SnapshotRefreshTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        (self.root / "App.cs").write_text("class App {}", encoding="utf-8")
        from analysis_prepare import source_files
        self.hashes = source_files(self.root)
        self.report = report_dir(self.root)
        self.snapshot = {"schema_version": 1, "git_revision": "old",
                         "source_hashes": self.hashes, "excluded_paths": []}
        _write(self.report / "analysis/review-snapshot.json", self.snapshot)
        _write(self.report / "analysis/structure-index.json", {
            "source_hashes": self.hashes,
            "rule_candidates": {"App.cs": [{"rule_id": "AC-01"}]},
            "typed_relationships": [], "cross_file_call_hints": {},
        })
        from review_snapshot import rule_scopes
        self.scopes = rule_scopes()
        self.assessment = {"checks": [
            {"id": rid, "status": "review", "evidence": [],
             "execution": {"state": "completed", "inspected_paths": [],
                           "methods": ["read_source"], "summary": "reviewed"}}
            for rid in self.scopes],
            "file_reviews": [],
            "findings": [{"id": "finding-1", "title": "keep this finding"}]}
        _write(self.report / "assessment.json", self.assessment)
        _write(self.report / "analysis/rule-closures.json", {
            "AU-09": {"status": "review", "summary": "preserve unrelated closure"},
            "AC-01": {"status": "review", "summary": "invalidate affected closure"},
        })

    def test_git_only_refresh_retains_findings_closures_and_no_rechecks(self):
        with patch("review_snapshot._revision", return_value="new"):
            self.assertTrue(any("SHA256 均未異動" in e for e in snapshot_errors(self.root)))
            refresh_snapshot(self.root)
            self.assertEqual(snapshot_errors(self.root), [])
        self.assertEqual(_read(self.report / "analysis/rule-closures.json")["AC-01"]["status"],
                         "review")
        self.assertFalse((self.report / "analysis/recheck-required.json").exists())
        self.assertEqual(_read(self.report / "assessment.json")["findings"],
                         self.assessment["findings"])

    def test_changed_code_invalidates_only_affected_closures_and_records_provenance(self):
        (self.root / "App.cs").write_text("class App { void Change() {} }", encoding="utf-8")
        with patch("review_snapshot._revision", return_value="old"):
            refresh_snapshot(self.root)
        ledger = _read(self.report / "analysis/recheck-required.json")
        self.assertEqual(ledger["schema_version"], 2)
        self.assertIn("AC-01", ledger["rule_ids"])
        self.assertIn("DP-01", ledger["rule_ids"])
        self.assertNotIn("AU-09", ledger["rule_ids"])
        self.assertEqual(ledger["changed_source_paths"], ["App.cs"])
        self.assertEqual(set(_read(self.report / "analysis/rule-closures.json")), {"AU-09"})
        self.assertEqual(_read(self.report / "assessment.json")["findings"],
                         self.assessment["findings"])

    def test_new_review_receipt_can_clear_only_its_authorized_rule(self):
        from control_effectiveness import snapshot_fingerprint
        target_check = next(x for x in self.assessment["checks"] if x["id"] == "AC-01")
        target_check["evidence"] = [{"kind": "source", "path": "App.cs",
                                     "line_start": 1, "line_end": 1}]
        _write(self.report / "assessment.json", self.assessment)
        _write(self.report / "analysis/recheck-required.json", {
            "schema_version": 2,
            "rule_ids": ["AC-01", "AU-09"],
            "changed_source_paths": ["App.cs"]})
        updated_check = copy.deepcopy(target_check)
        updated_check["execution"]["summary"] = (
            "已重新閱讀當前 App.cs 並核對實際控制來源，重新記錄分析方法與適用範圍。")
        receipt = {"snapshot_fingerprint": snapshot_fingerprint(self.snapshot),
                   "source_hashes": dict(self.hashes),
                   "verification_summary": "已重新閱讀 App.cs 的目前來源及實際執行位置，確認本次核對來源版本與先前紀錄有明確區別。"}
        payload = self.report / "refresh-proof.json"
        payload.write_text(json.dumps({"checks": [updated_check],
                                       "recheck_proof": {"AC-01": receipt}},
                                      ensure_ascii=False), encoding="utf-8")
        with patch("review_snapshot._revision", return_value="old"):
            stage(self.root, payload)
            result = integrate(self.root, allow_revision=True)
        self.assertEqual(result["applied"], 1)
        ledger = _read(self.report / "analysis/recheck-required.json")
        self.assertEqual(ledger["rule_ids"], ["AU-09"])
        self.assertEqual(len(ledger["verified_rechecks"]["AC-01"]["receipt_sha256"]), 64)
        self.assertEqual(_read(self.report / "assessment.json")["findings"],
                         self.assessment["findings"])

    def test_replayed_completed_check_cannot_clear_recheck(self):
        from control_effectiveness import snapshot_fingerprint
        target_check = next(x for x in self.assessment["checks"] if x["id"] == "AC-01")
        target_check["evidence"] = [{"kind": "source", "path": "App.cs",
                                     "line_start": 1, "line_end": 1}]
        _write(self.report / "assessment.json", self.assessment)
        _write(self.report / "analysis/recheck-required.json", {
            "schema_version": 2, "rule_ids": ["AC-01"],
            "changed_source_paths": ["App.cs"]})
        from review_snapshot import _revision
        with patch("review_snapshot._revision", return_value="old"):
            # Even a current, plausible hash receipt cannot authorize a replay
            # of an unchanged completed verdict.
            receipt = {"snapshot_fingerprint": snapshot_fingerprint(self.snapshot),
                       "source_hashes": dict(self.hashes),
                       "verification_summary": "已重新閱讀相關來源檔及行號，並將實際控制證據與原本結論逐項核對完畢。"}
            payload = self.report / "payload.json"
            payload.write_text(json.dumps({"checks": [copy.deepcopy(target_check)],
                                           "recheck_proof": {"AC-01": receipt}},
                                          ensure_ascii=False), encoding="utf-8")
            stage(self.root, payload)
            with self.assertRaisesRegex(ValueError, "重新查核須新增實際證據"):
                integrate(self.root, allow_revision=True)
        self.assertEqual(_read(self.report / "analysis/recheck-required.json")["rule_ids"],
                         ["AC-01"])
        self.assertEqual(_read(self.report / "assessment.json")["findings"],
                         self.assessment["findings"])


class AuthoritativeDiagnosisTests(unittest.TestCase):
    def test_source_recheck_uses_structured_ledger_not_message_examples(self):
        message = "第一輪：來源異動後仍有待重新查核規則：AC-01、AU-09"
        result = summarize([message], required_recheck_rules=["AC-01", "AU-09"])
        self.assertEqual(result["recheck_rule_ids"], ["AC-01", "AU-09"])
        self.assertEqual(result["blockers"][0]["rule_ids"], ["AC-01", "AU-09"])
        self.assertEqual(result["blockers"][0]["category"], "integrity")
        other = summarize([message], required_recheck_rules=["AC-01"])
        self.assertNotEqual(result["blocker_signature"], other["blocker_signature"])

    def test_diagnose_uses_recheck_file_even_if_message_contains_examples(self):
        from review_blockers import diagnose
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            ledger = root / "reports/security-code-review/analysis/recheck-required.json"
            _write(ledger, {"rule_ids": ["AU-09"]})
            with patch("adversarial_recheck.first_pass_issues",
                       return_value=["第一輪：來源異動後仍有待重新查核規則：AC-01、AU-09"]):
                result = diagnose(root, {"checks": []})
        self.assertEqual(result["recheck_rule_ids"], ["AU-09"])
        self.assertEqual(result["blockers"][0]["rule_ids"], ["AU-09"])

    def test_diagnostic_preview_does_not_attribute_untrusted_ids(self):
        message = "其他錯誤範例：AC-01、AU-09"
        self.assertEqual(summarize([message])["recheck_rule_ids"], [])


if __name__ == "__main__":
    unittest.main()
