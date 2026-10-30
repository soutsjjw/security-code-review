"""Security regressions for Wave 0–4 transaction boundaries and sampling."""
from __future__ import annotations
from contextlib import ExitStack
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/lib"))
from review_repair_waves import _payload_scope, _sample_policy, apply_second_pass
from review_waves_state import evidence_state, formal_diff


def fingerprints():
    return {"checks": {"AC-01": {"digest": "a", "status": "review"}},
            "closures": {}, "control_verifications": {},
            "decision_audits": {}, "file_reviews": {}, "findings": {}}


class RepairWavesSecurityTests(unittest.TestCase):
    def test_file_rule_evidence_cannot_cross_batches(self):
        existing = {"file_reviews": [{"path": "Service.cs", "rule_reviews": [
            {"rule_id": "AC-01", "summary": "original"},
            {"rule_id": "AU-01", "summary": "untouched"},
        ]}]}
        permitted = {"file_reviews": [{"path": "Service.cs", "rule_reviews": [
            {"rule_id": "AC-01", "summary": "new evidence"},
            {"rule_id": "AU-01", "summary": "untouched"},
        ]}]}
        _payload_scope(permitted, {"rule_ids": ["AC-01"]},
                       allow_finding_revision=False, previous=existing)
        forbidden = json.loads(json.dumps(permitted))
        forbidden["file_reviews"][0]["rule_reviews"][1]["summary"] = "tampered"
        with self.assertRaisesRegex(ValueError, "跨批次"):
            _payload_scope(forbidden, {"rule_ids": ["AC-01"]},
                           allow_finding_revision=False, previous=existing)

    def test_shared_file_metadata_must_not_be_rewritten(self):
        old = {"file_reviews": [{"path": "Service.cs", "summary": "original",
                                 "rule_reviews": [{"rule_id": "AU-01", "summary": "evidence"}]}]}
        newer = {"file_reviews": [{"path": "Service.cs", "summary": "changed",
                                   "rule_reviews": [{"rule_id": "AU-01", "summary": "evidence"}]}]}
        with self.assertRaisesRegex(ValueError, "跨批次"):
            _payload_scope(newer, {"rule_ids": ["AC-01"]},
                           allow_finding_revision=False, previous=old)

    def test_new_file_must_not_introduce_other_rule_evidence(self):
        row = {"file_reviews": [{"path": "New.cs",
                                  "rule_reviews": [{"rule_id": "AU-01", "summary": "x"}]}]}
        with self.assertRaisesRegex(ValueError, "跨批次"):
            _payload_scope(row, {"rule_ids": ["AC-01"]},
                           allow_finding_revision=False, previous={"file_reviews": []})

    def test_unattributed_file_review_is_not_a_batch_repair(self):
        payload = {"file_reviews": [{"path": "New.cs", "rule_reviews": []}]}
        with self.assertRaisesRegex(ValueError, "缺少可核對的規則歸屬"):
            _payload_scope(payload, {"rule_ids": ["AC-01"]},
                           allow_finding_revision=False,
                           previous={"file_reviews": []})

    def test_external_control_and_finding_revisions_force_sampling(self):
        prior = fingerprints()
        after = json.loads(json.dumps(prior))
        after["control_verifications"]["AC-01"] = "changed"
        after["findings"]["F1"] = {"digest": "new", "owners": ["AC-01"]}
        changed, mandatory = formal_diff(prior, after)
        self.assertEqual(changed, {"AC-01"})
        self.assertEqual(mandatory, {"AC-01"})

    def test_unattributed_file_revisions_are_conservatively_scoped(self):
        prior = fingerprints()
        after = json.loads(json.dumps(prior))
        after["file_reviews"]["unknown.cs"] = {"digest": "changed", "owners": []}
        changed, mandatory = formal_diff(prior, after)
        self.assertEqual(changed, {"AC-01"})
        self.assertEqual(mandatory, set())

    def test_sampling_covers_every_populated_risk_stratum(self):
        rules = ["AC-01", "DP-01", "LG-01", "BC-01"]
        checks = [{"id": r, "status": "review" if r == "DP-01" else "pass"} for r in rules]
        policy = _sample_policy(rules, [], "seed", {"checks": checks})
        self.assertEqual(policy["rule_count"], 4)
        self.assertEqual(policy["strata_population"],
                         {"high": 1, "medium": 1, "low": 2})
        self.assertGreaterEqual(policy["strata_selected"]["high"], 1)
        self.assertGreaterEqual(policy["strata_selected"]["medium"], 1)
        self.assertGreaterEqual(policy["strata_selected"]["low"], 1)

    def test_sampling_strata_follow_rule_review_tier(self):
        # IN-01 屬 review_tier=high；DP-01 與 IN-05 為 standard，不再因類別前綴升級。
        rules = ["IN-01", "IN-05", "DP-01", "PD-02"]
        checks = [{"id": r, "status": "pass"} for r in rules]
        policy = _sample_policy(rules, [], "seed", {"checks": checks})
        self.assertEqual(policy["strata_population"], {"high": 2, "medium": 0, "low": 2})

    def test_formal_manifest_and_all_tracked_versions_detect_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            analysis = root / "reports/security-code-review/analysis"
            analysis.mkdir(parents=True)
            (analysis.parent / "assessment.json").write_text('{"checks":[]}')
            (analysis / "review-snapshot.json").write_text('{"source_hashes":{}}')
            (analysis / "rule-closures.json").write_text('{}')
            (analysis / "integrity-manifest.json").write_text('{"head":"one"}')
            with patch("review_snapshot.snapshot_errors", return_value=[]), \
                 patch("evidence_integrity.errors", return_value=[]):
                before = evidence_state(root)
                (analysis / "rule-closures.json").write_text('{"AC-01":{}}')
                after = evidence_state(root)
                self.assertNotEqual(before, after)
                self.assertNotEqual(before["tracked_sha256"]["analysis/rule-closures.json"],
                                    after["tracked_sha256"]["analysis/rule-closures.json"])

    def _mock_second_pass(self, root, worklist):
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch("review_waves_state.load_state",
                                  return_value={"phase": "second_pass", "paused": False,
                                                "last_evidence": {"manifest_sha256": None},
                                                "formal_fingerprints": fingerprints()}))
        stack.enter_context(patch("review_waves_state.assert_state_current"))
        stack.enter_context(patch("review_waves_state.ensure_stage_clean"))
        stack.enter_context(patch("second_pass_layers.worklist", return_value=worklist))
        stack.enter_context(patch("review_waves_state.load_assessment",
                                  return_value={"checks": [], "file_reviews": []}))
        return stack

    def test_second_pass_rejects_unassigned_rule_or_path(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            p = root / "candidate.json"
            p.write_text(json.dumps({"adversarial_reviews": {"AU-02": {"evidence": []}}}))
            self._mock_second_pass(root, {"ready": True,
                "rule_tasks": [{"rule_id": "AC-01"}],
                "sample_tasks": [{"path": "Program.cs"}]})
            with self.assertRaisesRegex(ValueError, "不在目前第二輪工作批次"):
                apply_second_pass(root, p)

    def test_second_pass_calls_existing_formal_transaction_without_self_approval(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            p = root / "candidate.json"
            p.write_text(json.dumps({"adversarial_reviews": {"AC-01": {"hypotheses": []}}}))
            self._mock_second_pass(root, {"ready": True,
                "rule_tasks": [{"rule_id": "AC-01"}], "sample_tasks": []})
            with patch("review_safety.stage", return_value="staged") as stage, \
                 patch("review_safety.integrate", return_value={"applied": 1}) as integrate, \
                 patch("review_waves_state.evidence_state", return_value={"sha": "after"}), \
                 patch("review_waves_state.formal_fingerprints", return_value=fingerprints()), \
                 patch("review_waves_state.write_state"):
                result = apply_second_pass(root, p)
            stage.assert_called_once()
            integrate.assert_called_once()
            self.assertFalse(result["ready_for_report"])


if __name__ == "__main__":
    unittest.main()
