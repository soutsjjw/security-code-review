"""G1 / E2E: fail closed without real review artifacts, preserve Findings and shadow verdicts."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/lib"))
import flow_acceptance as gate
from control_effectiveness import snapshot_fingerprint

class FlowAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.target = self.root / "optimized"
        self.legacy = self.root / "legacy"
        self.before = self.root / "before.json"
        self.shadow_old = self.root / "shadow-old.json"
        self.shadow_new = self.root / "shadow-new.json"
        self.finding = {"id": "F-1", "title": "verified finding"}
        catalog = json.loads((ROOT / "rules.json").read_text(encoding="utf-8"))
        self.checks = [{"id": r["id"]} for r in catalog["rules"]]
        self.write(self.target / "reports/security-code-review/assessment.json",
                   {"findings": [self.finding], "checks": self.checks})
        self.write(self.legacy / "reports/security-code-review/assessment.json",
                   {"findings": [self.finding]})
        self.write(self.before, {"findings": [self.finding]})
        shadow = {"ready_for_second_pass": True, "pending_rule_ids": [],
                  "missing_source_file_count": 0, "recheck_rule_ids": [], "blockers": []}
        self.write(self.shadow_old, shadow)
        self.write(self.shadow_new, shadow)
        snapshot = {"git_revision": "test-revision", "source_hashes": {"Api.cs": "a"*64}}
        self.write(self.target / "reports/security-code-review/analysis/review-snapshot.json", snapshot)
        self.write(self.target / "reports/security-code-review/analysis/first-pass-baseline.json",
                   {"schema_version": 1, "snapshot_fingerprint": snapshot_fingerprint(snapshot),
                    "checks": {x["id"]: {"status": "review", "digest": "a"*64} for x in self.checks}})
        self.write(self.target / "reports/security-code-review/logs/latest.json",
                   {"run_id": "20261028-100000-abcd1234"})
        self.write(self.target / "reports/security-code-review/logs/boundary-baselines/"
                   "20261028-100000-abcd1234.json", {"inventory": {"boundary_level": "L3"}, "scripts": {}})

    def write(self, path, obj):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(obj), encoding="utf-8")

    def run_g1(self):
        return gate.g1(self.target, before_path=self.before,
                       shadow_legacy=self.shadow_old,
                       shadow_optimized=self.shadow_new,
                       legacy_target=self.legacy)

    def test_missing_real_first_pass_gate_never_accepted(self):
        result = self.run_g1()
        self.assertFalse(result["accepted"])
        self.assertFalse(next(x for x in result["checks"]
                              if x["id"] == "full_gate_passed")["passed"])

    def test_g1_conditional_L3_cannot_be_misrepresented_as_enforced(self):
        with patch("flow_acceptance.first_pass_issues", return_value=[]), \
             patch("flow_acceptance.integrity_errors", return_value=[]), \
             patch("flow_acceptance.snapshot_errors", return_value=[]), \
             patch("evidence_integrity.enabled", return_value=True), \
             patch("flow_acceptance.verify_run", return_value={"blocked_batches": []}):
            result = self.run_g1()
        self.assertTrue(result["accepted"])
        self.assertEqual(result["assurance"], "conditional-audit-only")
        self.assertNotEqual(result["assurance"], "verified")

    def test_finding_loss_and_shadow_diff_are_rejected(self):
        self.write(self.target / "reports/security-code-review/assessment.json",
                   {"findings": [], "checks": []})
        self.write(self.shadow_new, {"ready_for_second_pass": False, "blockers": []})
        result = self.run_g1()
        self.assertFalse(result["accepted"])
        checks = {x["id"]: x for x in result["checks"]}
        self.assertFalse(checks["findings_preserved"]["passed"])
        self.assertFalse(checks["shadow_equivalent"]["passed"])

    def test_pending_boundary_review_distinct_from_convergence_block(self):
        with patch("flow_acceptance.verify_run", return_value={"blocked_batches": ["batch-1"]}):
            result = self.run_g1()
        self.assertFalse(result["accepted"])
        self.assertEqual(result["status"], "blocked_pending_review")

    def test_fake_finding_amendment_cannot_hide_mutation(self):
        before = {"findings": [self.finding]}
        after = {"findings": [{"id": "F-1", "title": "changed"}],
                 "finding_amendments": [{"finding_id": "F-1",
                   "previous_sha256": "f" * 64, "updated_sha256": "e" * 64,
                   "reviewer": "fake", "reason": "a" * 41,
                   "previous_finding": self.finding}]}
        missing, changed = gate.preservation(before, after)
        self.assertEqual(missing, [])
        self.assertEqual(changed, ["F-1"])

    def test_e2e_always_delegates_to_existing_strict_gate(self):
        with patch("flow_acceptance.quality_measure", return_value={
            "quality_gate_passed": False, "measurement_source": "real_project_artifacts",
            "source_fingerprint": "sha", "coverage": {}, "verified_second_pass_count": 0,
            "finding_count": 3, "diagnostics": ["not complete"], "regressions": []}) as measure:
            out = gate.e2e(self.target)
        measure.assert_called_once()
        self.assertFalse(out["accepted"])
        self.assertEqual(out["status"], "blocked")

if __name__ == "__main__":
    unittest.main()
