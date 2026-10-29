"""First-pass completed transition: per-rule gate and legacy repair compatibility."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from batch_evidence_gate import completion_transition_errors
from cross_file_evidence import trace_errors


class CompletedEvidenceGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.target = Path(self.temp.name)
        self.before = {"checks": [
            {"id": "AC-01", "status": "pass", "execution": {"state": "pending"}}
        ]}
        self.after = {"checks": [
            {"id": "AC-01", "status": "pass", "execution": {"state": "completed"}}
        ]}
        self.before_closures = {}
        self.after_closures = {"AC-01": {"status": "pass"}}
        self.before_verifications = {}
        self.after_verifications = {"AC-01": {"status": "pass"}}
        self.before_audits = {}
        self.after_audits = {"AC-01": {"status": "pass"}}

    def evaluate(self):
        return completion_transition_errors(
            self.target, self.before, self.after,
            before_closures=self.before_closures, after_closures=self.after_closures,
            before_verifications=self.before_verifications,
            after_verifications=self.after_verifications,
            before_audits=self.before_audits, after_audits=self.after_audits,
        )

    def test_new_completion_uses_merged_uncommitted_sidecars(self):
        seen = []

        def closure(_target, _data, **kwargs):
            self.assertIs(kwargs["closures_override"], self.after_closures)
            self.assertIs(kwargs["verifications_override"], self.after_verifications)
            self.assertIs(kwargs["audits_override"], self.after_audits)
            seen.append("closure")
            return []

        def effectiveness(_target, _checks, **kwargs):
            self.assertIs(kwargs["records_override"], self.after_verifications)
            self.assertIs(kwargs["audits_override"], self.after_audits)
            self.assertIs(kwargs["assessment_override"], self.after)
            seen.append("outcome")
            return []

        def adjudication(_target, _checks, **kwargs):
            self.assertIs(kwargs["audits_override"], self.after_audits)
            seen.append("decision")
            return []

        with patch("review_completion.completion_errors", return_value=[]), \
             patch("review_decision.decision_quality_errors", return_value=[]), \
             patch("review_safety.closure_errors", side_effect=closure), \
             patch("control_effectiveness.verification_errors", side_effect=effectiveness), \
             patch("decision_adjudication.adjudication_errors", side_effect=adjudication):
            self.assertEqual(self.evaluate(), [])
        self.assertEqual(seen, ["closure", "outcome", "decision"])

    def test_new_completion_fails_for_each_missing_contract(self):
        for name, mocked, message in (
            ("closure", "review_safety.closure_errors", "Q2 無效控制鏈"),
            ("control", "control_effectiveness.verification_errors", "Q3 缺少結果證據"),
            ("decision", "decision_adjudication.adjudication_errors", "P3 缺少責任紀錄"),
        ):
            with self.subTest(name=name), \
                 patch("review_completion.completion_errors", return_value=[]), \
                 patch("review_decision.decision_quality_errors", return_value=[]), \
                 patch("review_safety.closure_errors", return_value=[]), \
                 patch("control_effectiveness.verification_errors", return_value=[]), \
                 patch("decision_adjudication.adjudication_errors", return_value=[]):
                # Patch only the selected contract within the nested context.
                with patch(mocked, return_value=["AC-01: " + message]):
                    errors = self.evaluate()
                self.assertTrue(any(message in e and "新完成規則" in e for e in errors))

    def test_existing_valid_completed_cannot_regress(self):
        self.before["checks"][0]["execution"]["state"] = "completed"
        self.before_verifications = {"AC-01": {"status": "pass", "complete": True}}
        self.after_verifications = {"AC-01": {"status": "pass", "complete": False}}

        def verification(_target, _checks, **kwargs):
            proof = kwargs["records_override"]["AC-01"]
            return [] if proof.get("complete") else ["AC-01: P2 證據遭破壞"]

        with patch("review_completion.completion_errors", return_value=[]), \
             patch("review_decision.decision_quality_errors", return_value=[]), \
             patch("review_safety.closure_errors", return_value=[]), \
             patch("control_effectiveness.verification_errors", side_effect=verification), \
             patch("decision_adjudication.adjudication_errors", return_value=[]):
            self.assertIn("既有 completed 證據修訂新增阻塞", "；".join(self.evaluate()))

    def test_incomplete_legacy_sidecar_can_be_repaired_incrementally(self):
        self.before["checks"][0]["execution"]["state"] = "completed"

        def closure(_target, _checks, **kwargs):
            sidecars = kwargs["closures_override"]
            return (["AC-01: Q2 尚待補足來源行號"] if sidecars
                    else ["AC-01: 缺少 cross_file 結案"])

        with patch("review_completion.completion_errors", return_value=[]), \
             patch("review_decision.decision_quality_errors", return_value=[]), \
             patch("review_safety.closure_errors", side_effect=closure), \
             patch("control_effectiveness.verification_errors", return_value=[]), \
             patch("decision_adjudication.adjudication_errors", return_value=[]):
            self.assertEqual(self.evaluate(), [])

    def test_pending_rule_is_not_force_closed(self):
        self.after["checks"][0]["execution"]["state"] = "pending"
        with patch("review_safety.closure_errors",
                   side_effect=AssertionError("pending rule should not be validated")):
            self.assertEqual(self.evaluate(), [])

    def test_q2_external_proof_considers_same_batch_verification(self):
        index = {"cross_file_evidence_version": 1}
        snapshot = {"source_hashes": {}}
        check = {"id": "AC-01", "status": "pass"}
        sidecar = {"AC-01": {"status": "pass", "control_proof_mode": "external_verified"}}
        with patch("control_effectiveness._external_pass_errors", return_value=[]) as verify:
            self.assertEqual(trace_errors(
                self.target, index, snapshot, check, {}, "cross_file",
                verifications_override=sidecar,
            ), [])
        verify.assert_called_once()


if __name__ == "__main__":
    unittest.main()
