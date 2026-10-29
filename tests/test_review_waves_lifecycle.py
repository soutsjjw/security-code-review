"""Additional P0–P2 Wave contracts, crash recovery and formal delivery gates."""
from __future__ import annotations
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from review_waves_contracts import work_contract, sample_chain_append, verify_sample_chain, independence_metadata
from review_waves_lifecycle import agent_next, reconcile, finalize


class WaveLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.evidence = {"assessment_sha256": "a" * 64,
                         "source_snapshot_sha256": "b" * 64,
                         "manifest_sha256": "c" * 64}
        self.fingerprints = {
            "checks": {"AC-01": {"digest": "old", "status": "review"}},
            "closures": {}, "control_verifications": {}, "decision_audits": {},
            "file_reviews": {}, "findings": {}}
        self.latest = {
            **self.fingerprints,
            "checks": {"AC-01": {"digest": "new", "status": "pass"}}}
        self.current = {"blocker_signature": "old", "blockers": [{
            "message": "AC-01: Q2 控制鏈不完整", "rule_ids": ["AC-01"],
            "category": "other"}]}
        self.cleared = {"blocker_signature": "new", "blockers": [],
                        "ready_for_second_pass": True}
        self.batch = {"batch_id": "execution-01", "rule_ids": ["AC-01"],
                      "task_ids": ["AC-01:P1"], "depends_on_batch_ids": []}
        self.state = {
            "schema_version": 2, "phase": "first_pass", "paused": False,
            "batches": [self.batch], "completed_batches": [],
            "tasks": [{"task_id": "AC-01:P1", "blocker_details": [{
                "message": "AC-01: Q2 控制鏈不完整", "rule_ids": ["AC-01"]}]}],
            "last_evidence": self.evidence, "formal_fingerprints": self.fingerprints,
            "initial_signature": "old", "observed_signature": "old",
            "observed_diagnostic": self.current, "changed_rules": [],
            "mandatory_rules": [], "sample_records": {}, "sample_chain": None,
            "inflight": {"phase": "first_pass", "batch_id": "execution-01",
                         "prior_evidence": self.evidence,
                         "prior_fingerprints": self.fingerprints}}

    def test_agent_packet_is_honest_about_native_execution(self):
        state = dict(self.state, inflight=None)
        task = work_contract(self.root, state)
        self.assertTrue(task["ready"])
        self.assertEqual(task["task"]["batch_id"], "execution-01")
        self.assertEqual(task["agent_capability"], "not-verified-by-this-script")
        self.assertIn("single-main-agent", task["fallback"])
        self.assertEqual(task["task_digest"], work_contract(self.root, state)["task_digest"])

    def test_agent_packet_does_not_fabricate_independence(self):
        state = dict(self.state, phase="second_pass", inflight=None)
        with self.assertRaises(ValueError):
            work_contract(self.root, state, second_pass={"ready": False})
        packet = work_contract(self.root, state, second_pass={
            "ready": True, "rule_tasks": [{"rule_id": "AC-01"}],
            "sample_tasks": [], "targeted_paths": ["Service.cs"]})
        self.assertEqual(packet["task"]["rule_ids"], ["AC-01"])
        self.assertFalse(independence_metadata(external_probe={"claimed": "L2"})["independent"])

    def test_sample_chain_detects_reordering_or_mutation(self):
        first = sample_chain_append(None, {"rule_id": "AC-01", "claim": "checked"},
                                    expected_manifest_sha256="c" * 64)
        second = sample_chain_append(first, {"rule_id": "AU-01", "claim": "checked"},
                                     expected_manifest_sha256="c" * 64)
        verify_sample_chain(second)
        second["entries"][0]["rule_id"] = "AU-02"
        with self.assertRaises(ValueError):
            verify_sample_chain(second)

    def test_sample_chain_rejects_different_manifest_version(self):
        first = sample_chain_append(None, {"rule_id": "AC-01"}, expected_manifest_sha256="c" * 64)
        with self.assertRaisesRegex(ValueError, "Manifest"):
            sample_chain_append(first, {"rule_id": "AU-01"},
                                expected_manifest_sha256="d" * 64)

    def test_reconcile_without_authorization_or_actual_commit_fails(self):
        with self.assertRaisesRegex(ValueError, "明確承認"):
            reconcile(self.root, acknowledged=False)
        with patch("review_repair_waves._load_state", return_value=self.state), \
             patch("review_repair_waves._evidence_state", return_value=self.evidence), \
             patch("review_repair_waves._formal_fingerprints", return_value=self.fingerprints):
            with self.assertRaisesRegex(ValueError, "未觀察到完成的正式證據"):
                reconcile(self.root, acknowledged=True)

    def test_reconcile_confirms_original_blocker_is_gone_without_replaying_stage(self):
        with patch("review_repair_waves._load_state", return_value=self.state), \
             patch("review_repair_waves._evidence_state", return_value=self.evidence), \
             patch("review_repair_waves._formal_fingerprints", return_value=self.latest), \
             patch("review_repair_waves._assessment", return_value={"checks": []}), \
             patch("review_blockers.diagnose", return_value=self.cleared), \
             patch("review_repair_waves._write_state") as save, \
             patch("review_safety.stage") as stage:
            result = reconcile(self.root, acknowledged=True)
        self.assertEqual(result["status"], "reconciled")
        self.assertEqual(result["phase"], "sample")
        self.assertIsNone(self.state["inflight"])
        save.assert_called_once()
        stage.assert_not_called()

    def test_reconcile_rejects_unrelated_formal_artifact_changes(self):
        before = dict(self.evidence, tracked_sha256={
            "assessment.json": "a" * 64,
            "analysis/first-pass-baseline.json": None,
        })
        after = dict(before, tracked_sha256={
            "assessment.json": "a" * 64,
            "analysis/first-pass-baseline.json": "b" * 64,
        })
        state = dict(self.state, inflight={**self.state["inflight"],
                                           "prior_evidence": before})
        with patch("review_repair_waves._load_state", return_value=state), \
             patch("review_repair_waves._evidence_state", return_value=after):
            with self.assertRaisesRegex(ValueError, "正式工件異動超出"):
                reconcile(self.root, acknowledged=True)

    def test_reconcile_rejects_out_of_scope_formal_changes(self):
        updated = {**self.latest,
                   "checks": {"AC-01": {"digest": "new", "status": "pass"},
                              "AU-01": {"digest": "unexpected", "status": "fail"}}}
        with patch("review_repair_waves._load_state", return_value=self.state), \
             patch("review_repair_waves._evidence_state", return_value=self.evidence), \
             patch("review_repair_waves._formal_fingerprints", return_value=updated), \
             patch("review_repair_waves._assessment", return_value={"checks": []}), \
             patch("review_blockers.diagnose", return_value=self.cleared):
            with self.assertRaisesRegex(ValueError, "超出批次授權"):
                reconcile(self.root, acknowledged=True)

    def test_interrupted_baseline_can_only_reconcile_real_formal_commit(self):
        old = {**self.fingerprints, "first_pass_baseline": None}
        new = {**old, "first_pass_baseline": "a" * 64}
        state = dict(self.state, phase="sample",
                     formal_fingerprints=old,
                     inflight={"phase": "baseline", "batch_id": "first-pass-baseline",
                               "prior_evidence": self.evidence,
                               "prior_fingerprints": old})
        with patch("review_repair_waves._load_state", return_value=state), \
             patch("review_repair_waves._evidence_state", return_value=self.evidence), \
             patch("review_repair_waves._formal_fingerprints", return_value=new), \
             patch("second_pass_layers.worklist",
                   return_value={"ready": True, "rules_total": 70, "rules_pending": 70}), \
             patch("review_repair_waves._write_state") as save:
            result = reconcile(self.root, acknowledged=True)
        self.assertTrue(result["baseline_reconciled"])
        self.assertEqual(state["phase"], "second_pass")
        self.assertIsNone(state["inflight"])
        save.assert_called_once()

    def test_final_report_needs_completed_second_pass(self):
        state = dict(self.state, phase="second_pass", inflight=None, sample_policy={
            "selected_rules": []})
        with patch("review_repair_waves._load_state", return_value=state), \
             patch("review_repair_waves._assert_state_current"), \
             patch("second_pass_layers.worklist", return_value={
                 "ready": True, "rules_total": 70, "rules_pending": 1, "samples_pending": 0}):
            with self.assertRaisesRegex(ValueError, "反向複核"):
                finalize(self.root)

    def test_agent_work_contract_does_not_skip_sampling(self):
        state = dict(self.state, phase="sample", inflight=None)
        result = work_contract(self.root, state)
        self.assertFalse(result["ready"])
        self.assertEqual(result["phase"], "sample")

    def test_second_pass_only_formal_commit_can_be_reconciled(self):
        old = {**self.fingerprints, "adversarial_reviews": None}
        new = {**old, "adversarial_reviews": "a" * 64}
        state = dict(self.state, phase="second_pass",
                     formal_fingerprints=old,
                     inflight={"phase": "second_pass", "batch_id": "second-pass",
                               "prior_evidence": self.evidence,
                               "prior_fingerprints": old})
        with patch("review_repair_waves._load_state", return_value=state), \
             patch("review_repair_waves._evidence_state", return_value=self.evidence), \
             patch("review_repair_waves._formal_fingerprints", return_value=new), \
             patch("second_pass_layers.worklist",
                   return_value={"ready": True, "rules_pending": 1,
                                 "samples_pending": 1}), \
             patch("review_repair_waves._write_state") as save:
            result = reconcile(self.root, acknowledged=True)
        self.assertEqual(result["phase"], "second_pass")
        self.assertEqual(result["status"], "reconciled")
        self.assertIsNone(state["inflight"])
        save.assert_called_once()

    def test_finalization_calls_official_report_after_full_gate(self):
        state = dict(self.state, phase="second_pass", inflight=None,
                     sample_policy={"selected_rules": []})
        report_dir = self.root / "reports/security-code-review"
        report_dir.mkdir(parents=True, exist_ok=True)
        (report_dir / "report.json").write_text("{}", encoding="utf-8")
        (report_dir / "CodeReview_20261029.html").write_text(
            "<html>validated fixture</html>", encoding="utf-8")
        with patch("review_repair_waves._load_state", return_value=state), \
             patch("review_repair_waves._assert_state_current"), \
             patch("second_pass_layers.worklist", return_value={
                 "ready": True, "rules_total": 70, "rules_pending": 0,
                 "samples_pending": 0}), \
             patch("review_repair_waves._assessment",
                   return_value={"assessment_date": "2026-10-29", "checks": []}), \
             patch("review_queue.load_rules", return_value=({}, [])), \
             patch("review_queue.build_queue", return_value={"ready_for_report": True}), \
             patch("review_safety.safety_errors", return_value=[]), \
             patch("review_repair_waves._stage_clean"), \
             patch("subprocess.run") as official:
            official.return_value.returncode = 0
            result = finalize(self.root)
        self.assertEqual(result["status"], "validated")
        self.assertEqual(result["independence"]["assurance_level"], "L0")
        self.assertFalse(result["independence"]["independent"])
        official.assert_called_once()

    def test_inflight_state_rejects_new_agent_work(self):
        from review_repair_waves import _assert_state_current
        with patch("review_repair_waves._evidence_state",
                   return_value=self.evidence):
            with self.assertRaisesRegex(ValueError, "待對帳"):
                _assert_state_current(self.root, self.state)

    def test_formal_report_requires_full_ready_queue(self):
        state = dict(self.state, phase="second_pass", inflight=None, sample_policy={
            "selected_rules": []})
        with patch("review_repair_waves._load_state", return_value=state), \
             patch("review_repair_waves._assert_state_current"), \
             patch("second_pass_layers.worklist", return_value={
                 "ready": True, "rules_total": 70, "rules_pending": 0, "samples_pending": 0}), \
             patch("review_repair_waves._assessment", return_value={"checks": []}), \
             patch("review_queue.load_rules", return_value=({}, [])), \
             patch("review_queue.build_queue", return_value={"ready_for_report": False}):
            with self.assertRaisesRegex(ValueError, "ready_for_report"):
                finalize(self.root)


if __name__ == "__main__":
    unittest.main()
