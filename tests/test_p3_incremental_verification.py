"""P3 incremental recheck plans: never infer formal pass from a partial scan."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import incremental_verification as p3

class IncrementalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        folder = self.root / "reports/security-code-review"
        (folder / "analysis").mkdir(parents=True)
        self.hashes = {"Controller.cs": "a"*64, "Service.cs": "b"*64,
                       "Unrelated.cs": "c"*64}
        self.snapshot = {"source_hashes": self.hashes, "git_revision": "rev"}
        self.index = {
            "source_hashes": self.hashes,
            "typed_relationships": [{"source": "Controller.cs", "target": "Service.cs"}],
            "cross_file_call_hints": {},
        }
        self.assessment = {
            "checks": [
                {"id": "AC-08", "execution": {"inspected_paths": ["Controller.cs"]},
                 "evidence": [{"path": "Controller.cs"}]},
                {"id": "AU-01", "execution": {"inspected_paths": ["Unrelated.cs"]},
                 "evidence": [{"path": "Unrelated.cs"}]},
                {"id": "BC-03", "execution": {"inspected_paths": []}, "evidence": []},
                {"id": "IN-01", "execution": {"inspected_paths": []}, "evidence": []},
            ],
            "file_reviews": [{"path": "Service.cs", "rule_reviews": [{"rule_id": "AC-08"}]},
                             {"path": "Unrelated.cs", "rule_reviews": [{"rule_id": "AU-01"}]}]
        }
        self.write("analysis/review-snapshot.json", self.snapshot)
        self.write("analysis/structure-index.json", self.index)
        self.write("assessment.json", self.assessment)
        self.write("analysis/rule-closures.json", {"AC-08": {
            "examined_paths": ["Controller.cs", "Service.cs"],
            "control_trace": {"nodes": [{"path": "Service.cs"}]}}})
        self.scopes = {"AC-08": "cross_file", "AU-01": "local",
                       "BC-03": "project", "IN-01": "local"}

    def write(self, path, obj):
        f = self.root / "reports/security-code-review" / path
        f.write_text(json.dumps(obj), encoding="utf-8")

    def invoke(self, changes, prior=True, **kwargs):
        fingerprint = p3.contract_fingerprint(ROOT, "L3") if prior else "old"
        with patch.object(p3, "rule_scopes", return_value=self.scopes), \
             patch.object(p3, "__file__", str(ROOT / "scripts/incremental_verification.py")):
            return p3.plan(self.root, changes, previous_contract=fingerprint, **kwargs)

    def test_typed_chain_expands_and_preserves_global_scope(self):
        result = self.invoke({"changed_paths": ["Controller.cs"]})
        self.assertFalse(result["full_recheck"])
        self.assertEqual(result["affected_rules"], ["AC-08", "BC-03"])
        self.assertIn("Service.cs", result["affected_paths"])
        self.assertIn("AU-01", result["sample_rules"])
        self.assertFalse(result["full_gate_passed"])
        self.assertFalse(result["ready_for_second_pass"])

    def test_missing_provenance_forces_full(self):
        result = self.invoke({"changed_rule_ids": ["AC-08"]}, prior=False)
        self.assertTrue(result["full_recheck"])
        self.assertEqual(result["affected_rules"], sorted(self.scopes))
        self.assertFalse(result["full_gate_passed"])

    def test_changed_rule_feature_or_schema_invalidates(self):
        first = p3.contract_fingerprint(ROOT, "L3")
        self.assertNotEqual(first, p3.contract_fingerprint(ROOT, "L2"))
        result = self.invoke({"changed_artifacts": ["schemas/assessment.schema.json"]})
        self.assertTrue(result["full_recheck"])
        self.assertEqual(result["reason"], "unproven-artifact-impact")

    def test_untrusted_graph_forces_full(self):
        self.index["cross_file_call_hints"] = {"Controller.cs": [
            {"possible_targets": [{"path": "Missing.cs"}]}]}
        self.write("analysis/structure-index.json", self.index)
        result = self.invoke({"changed_paths": ["Controller.cs"]})
        self.assertTrue(result["full_recheck"])
        self.assertEqual(result["reason"], "unresolved-callgraph-edges")

    def test_full_comparison_never_certifies_second_pass(self):
        incremental = self.invoke({"changed_paths": ["Controller.cs"]})
        with patch.object(p3, "diagnose", return_value={"blockers": [
              {"category": "control_trace", "rule_ids": ["AU-01"]}],
              "blocked_count": 1}), \
             patch("evidence_integrity.errors", return_value=[]), \
             patch("review_safety.snapshot_errors", return_value=[]):
            output = p3.full_comparison(self.root, incremental)
        self.assertFalse(output["full_gate_passed"])
        self.assertFalse(output["ready_for_second_pass"])
        # AU-01 is in risk-weighted sample, so discovered blocker is not hidden.
        self.assertEqual(output["unexpected_full_blocker_categories"], [])

if __name__ == "__main__":
    unittest.main()
