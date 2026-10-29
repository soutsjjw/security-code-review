"""Wave 0–4 orchestrator: fail-closed coverage, authorized writes and sampling."""
from __future__ import annotations

from datetime import date
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from review_repair_waves import (
    STATE, _batch_blockers, _payload_scope, _sample_policy, _write_state,
    _load_state, _next_batch, start, next_work, apply_batch, sample_plan,
    record_sample, resume_after_investigation, begin_second_pass, verify_second_pass,
)


def b(message, rule="AC-01"):
    return {"message": message, "rule_ids": [rule], "category": "other"}


class RepairWavesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.audit = {"assessment_sha256": "a" * 64, "source_snapshot_sha256": "b" * 64}
        self.base_fp = {"checks": {"AC-01": {"digest": "old", "status": "review"}},
                        "file_reviews": {}, "findings": {}, "closures": {},
                        "control_verifications": {}, "decision_audits": {}}
        self.updated_fp = {**self.base_fp, "checks":
                           {"AC-01": {"digest": "new", "status": "pass"}}}
        self.first = {"blocker_signature": "first", "blocked_count": 1,
                      "ready_for_second_pass": False, "blockers": [
                          b("AC-01: Q2 控制鏈不完整")]}
        self.last = {"blocker_signature": "last", "blocked_count": 0,
                     "ready_for_second_pass": True, "blockers": []}
        self.batch = {"batch_id": "execution-01", "rule_ids": ["AC-01"],
                      "task_ids": ["AC-01:P1"], "depends_on_batch_ids": []}
        self.task = {"task_id": "AC-01:P1", "rule_ids": ["AC-01"],
                     "blocker_details": [dict(index=0, **self.first["blockers"][0])]}
        self.plan = {"task_coverage": {"valid": True}, "execution_batches": [self.batch],
                     "rule_repair_tasks": [self.task]}

    def _start(self):
        with patch("review_repair_waves._evidence_state", return_value=self.audit), \
             patch("review_repair_waves._stage_clean"),
             patch("review_repair_waves._formal_fingerprints", return_value=self.base_fp), \
             patch("review_repair_waves._diagnose_and_plan",
                   return_value=(self.first, self.plan)):
            return start(self.root)

    def test_start_is_checkpointed_and_does_not_erase_prior_state(self):
        result = self._start()
        self.assertEqual(result["next_batch"]["batch_id"], "execution-01")
        self.assertEqual(_load_state(self.root)["last_evidence"], self.audit)
        with self.assertRaisesRegex(ValueError, "已有 checkpoint"):
            self._start()

    def test_start_rejects_invalid_task_coverage(self):
        self.plan["task_coverage"]["valid"] = False
        with patch("review_repair_waves._evidence_state", return_value=self.audit), \
             patch("review_repair_waves._stage_clean"),
             patch("review_repair_waves._formal_fingerprints", return_value=self.base_fp), \
             patch("review_repair_waves._diagnose_and_plan",
                   return_value=(self.first, self.plan)):
            with self.assertRaisesRegex(ValueError, "無法完整排程"):
                start(self.root)
        self.assertFalse((self.root / STATE).exists())

    def test_initially_clear_diagnostics_go_directly_to_sampling(self):
        self.plan["execution_batches"] = []
        with patch("review_repair_waves._evidence_state", return_value=self.audit), \
             patch("review_repair_waves._stage_clean"),
             patch("review_repair_waves._formal_fingerprints", return_value=self.base_fp), \
             patch("review_repair_waves._diagnose_and_plan",
                   return_value=(self.last, self.plan)):
            result = start(self.root)
        self.assertEqual(result["phase"], "sample")

    def test_rejects_unauthorized_batch_or_formal_payload_scope(self):
        self._start()
        payload = self.root / "candidate.json"
        payload.write_text(json.dumps({"checks": [{"id": "AU-01"}]}), encoding="utf-8")
        with patch("review_repair_waves._evidence_state", return_value=self.audit), \
             patch("review_repair_waves._assessment", return_value={"checks": [], "file_reviews": []}):
            with self.assertRaisesRegex(ValueError, "順序"):
                apply_batch(self.root, "execution-02", payload, allow_revision=True)
            with self.assertRaisesRegex(ValueError, "非本批規則"):
                apply_batch(self.root, "execution-01", payload, allow_revision=True)
        with self.assertRaisesRegex(ValueError, "明確 --allow-revision"):
            apply_batch(self.root, "execution-01", payload, allow_revision=False)

    def test_formal_stage_integrate_and_stable_state_handoff(self):
        self._start()
        payload = self.root / "candidate.json"
        payload.write_text(json.dumps({"checks": [{"id": "AC-01", "status": "pass"}]}),
                           encoding="utf-8")
        before = {"checks": [{"id": "AC-01", "status": "review"}], "findings": []}
        after = {"checks": [{"id": "AC-01", "status": "pass"}], "findings": []}
        with patch("review_repair_waves._evidence_state", return_value=self.audit), \
             patch("review_repair_waves._stage_clean"),
             patch("review_repair_waves._formal_fingerprints", return_value=self.base_fp), \
             patch("review_repair_waves._assessment", side_effect=[before, after]),
             patch("review_repair_waves._formal_fingerprints", return_value=self.base_fp),
             patch("review_repair_waves._formal_fingerprints", return_value=self.updated_fp), \
             patch("review_blockers.diagnose", side_effect=[self.first, self.last]), \
             patch("review_safety.stage", return_value="staged.json") as stage_mock, \
             patch("review_safety.integrate", return_value={"applied": 1}) as integrate_mock:
            result = apply_batch(self.root, "execution-01", payload, allow_revision=True)
        self.assertTrue(result["batch_completed"])
        self.assertEqual(result["phase"], "sample")
        self.assertEqual(_load_state(self.root)["changed_rules"], ["AC-01"])
        stage_mock.assert_called_once()
        integrate_mock.assert_called_once()

    def test_regression_pause_preserves_formal_state_and_does_not_auto_rollback(self):
        self._start()
        payload = self.root / "candidate.json"
        payload.write_text(json.dumps({"checks": [{"id": "AC-01", "status": "review"}]}),
                           encoding="utf-8")
        before = {"checks": [{"id": "AC-01", "status": "review"}], "findings": []}
        after = dict(before)
        with patch("review_repair_waves._evidence_state", return_value=self.audit), \
             patch("review_repair_waves._stage_clean"),
             patch("review_repair_waves._formal_fingerprints", return_value=self.base_fp), \
             patch("review_repair_waves._assessment", side_effect=[before, after]), \
             patch("review_blockers.diagnose", side_effect=[self.first, self.first]), \
             patch("review_safety.stage"), \
             patch("review_safety.integrate", return_value={"applied": 1}):
            result = apply_batch(self.root, "execution-01", payload, allow_revision=True)
        self.assertTrue(result["paused"])
        self.assertEqual(result["completed_batch_count"], 0)

    def test_resume_needs_explicit_confirmation_and_new_authoritative_diagnosis(self):
        self._start()
        state = _load_state(self.root)
        state["paused"] = True
        _write_state(self.root / STATE, state)
        with self.assertRaises(ValueError):
            resume_after_investigation(self.root, acknowledged=False)
        with patch("review_repair_waves._evidence_state", return_value=self.audit), \
             patch("review_repair_waves._assessment", return_value={"checks": []}), \
             patch("review_repair_waves._formal_fingerprints", return_value=self.updated_fp), \
             patch("review_blockers.diagnose", return_value=self.last):
            result = resume_after_investigation(self.root, acknowledged=True)
        self.assertEqual(result["phase"], "sample")
        self.assertEqual(result["completed_batch_count"], 1)

    def test_sample_selection_minimum_and_mandatory_high_risk(self):
        checks = [{"id": f"AC-{i:02d}", "status": "review"} for i in range(1, 21)]
        mandatory = ["AC-01", "AC-03", "AC-05", "AC-07", "AC-09", "AC-11"]
        result = _sample_policy([c["id"] for c in checks], mandatory, "signature",
                                {"checks": checks})
        self.assertEqual(result["minimum_sample_count"], 5)
        self.assertEqual(set(result["selected_rules"]), set(mandatory))
        self.assertEqual(result, _sample_policy([c["id"] for c in checks], mandatory,
                                                "signature", {"checks": checks}))

    def test_all_sampled_rules_require_explicit_receipts(self):
        self._start()
        state = _load_state(self.root)
        state["phase"] = "sample"
        state["completed_batches"] = ["execution-01"]
        state["changed_rules"] = ["AC-01"]
        _write_state(self.root / STATE, state)
        with patch("review_repair_waves._evidence_state", return_value=self.audit), \
             patch("review_repair_waves._assessment",
                   return_value={"checks": [{"id": "AC-01", "status": "pass"}]}):
            plan = sample_plan(self.root)
        self.assertEqual(plan["sampling"]["selected_rules"], ["AC-01"])
        self.assertEqual(plan["remaining_rules"], ["AC-01"])

    def test_second_pass_cannot_begin_without_samples(self):
        self._start()
        state = _load_state(self.root)
        state["phase"] = "sample"
        state["completed_batches"] = ["execution-01"]
        state["sample_policy"] = {"selected_rules": ["AC-01"]}
        _write_state(self.root / STATE, state)
        with patch("review_repair_waves._evidence_state", return_value=self.audit):
            with self.assertRaisesRegex(ValueError, "抽樣未全部完成"):
                begin_second_pass(self.root)

    def test_source_bound_sample_receipt_and_formal_second_pass_handoff(self):
        self._start()
        source = self.root / "Service.cs"
        source.write_text("public class Service {}\n", encoding="utf-8")
        sha = hashlib.sha256(source.read_bytes()).hexdigest()
        report = self.root / "reports/security-code-review/analysis"
        report.mkdir(parents=True)
        (report / "source-snapshot.json").write_text(json.dumps({
            "source_hashes": {"Service.cs": sha}}), encoding="utf-8")
        # The formal SNAPSHOT path is always imported from review_safety.
        state = _load_state(self.root)
        state["phase"] = "sample"
        state["completed_batches"] = ["execution-01"]
        state["changed_rules"] = ["AC-01"]
        state["sample_policy"] = {"selected_rules": ["AC-01"]}
        _write_state(self.root / STATE, state)
        receipt = self.root / "receipt.json"
        receipt.write_text(json.dumps({
            "rule_id": "AC-01", "reviewer": "Human Reviewer",
            "reviewed_on": date.today().isoformat(), "outcome": "verified",
            "review_summary": "逐行核對已提交的控制邏輯，重讀實際來源、可能繞過路徑與設定覆寫，並確認此項沒有新增弱點。",
            "evidence": {"path": "Service.cs", "line_start": 1, "line_end": 1}
        }, ensure_ascii=False), encoding="utf-8")
        with patch("review_repair_waves._evidence_state", return_value=self.audit), \
             patch("review_safety.SNAPSHOT", Path("analysis/source-snapshot.json")), \
             patch("review_repair_waves._assessment", return_value={
                 "checks": [{"id": "AC-01", "execution": {
                     "inspected_paths": ["Service.cs"]}}], "file_reviews": []}), \
             patch("source_reader.read_source_text", return_value=("public class Service {}", "utf-8")):
            result = record_sample(self.root, receipt)
        self.assertEqual(result["remaining_rules"], [])
        with patch("review_repair_waves._evidence_state", return_value=self.audit), \
             patch("review_repair_waves._assessment", return_value={"checks": []}), \
             patch("review_blockers.diagnose", return_value=self.first):
            with self.assertRaisesRegex(ValueError, "權威第一輪守門"):
                begin_second_pass(self.root)
        state = _load_state(self.root)
        state["observed_signature"] = self.last["blocker_signature"]
        _write_state(self.root / STATE, state)
        with patch("review_repair_waves._evidence_state", return_value=self.audit), \
             patch("review_repair_waves._assessment", return_value={"checks": []}), \
             patch("review_blockers.diagnose", return_value=self.last), \
             patch("adversarial_recheck.begin_second_pass", return_value={"baseline": "ok"}) as begin, \
             patch("second_pass_layers.worklist", return_value={"ready": True, "rules_pending": 70}):
            result = begin_second_pass(self.root)
        self.assertEqual(result["second_pass"]["rules_pending"], 70)
        self.assertEqual(_load_state(self.root)["phase"], "second_pass")
        begin.assert_called_once()

    def test_no_fabricated_second_pass_complete_from_empty_worklist(self):
        self._start()
        state = _load_state(self.root)
        state["phase"] = "second_pass"
        _write_state(self.root / STATE, state)
        with patch("review_repair_waves._evidence_state", return_value=self.audit), \
             patch("second_pass_layers.worklist", return_value={"ready": False}), \
             patch("review_repair_waves._assessment", return_value={}), \
             patch("review_safety.safety_errors", return_value=[]):
            result = verify_second_pass(self.root)
        self.assertFalse(result["ready_for_report"])


if __name__ == "__main__":
    unittest.main()
