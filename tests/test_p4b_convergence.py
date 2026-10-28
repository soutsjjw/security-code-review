"""P4-B thresholds trigger diagnosis rather than stopping healthy work."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import convergence_controller as p4b
import review_log

class ConvergenceTests(unittest.TestCase):
    def diagnostics(self, *, fingerprint="a"*64, count=1):
        return {"blocker_signature": fingerprint, "blocked_count": count,
                "blockers": [{"category": "control_trace", "rule_ids": ["AC-08"],
                              "message": "missing"}] if count else [],
                "root_cause_groups": [{"category": "control_trace", "blocker_count": count,
                                       "rule_ids": ["AC-08"]}] if count else []}
    def test_stable_fingerprint_triggers_diagnosing_not_run_stop(self):
        state = {}
        for _ in range(3):
            state = p4b.evaluate(state, self.diagnostics(), k=2, m=3)
        self.assertEqual(state["status"], "diagnosing")
        self.assertFalse(state["block_entire_run"])
        group = state["groups"][0]
        first = group["remaining_strategies"][0]
        updated = p4b.record_attempt(state, category=group["category"],
                                      group_key=group["group_key"],
                                      strategy_id=first["id"], evidence_receipt="reviewed source")
        with self.assertRaises(ValueError):
            p4b.record_attempt(updated, category=group["category"],
                               group_key=group["group_key"], strategy_id=first["id"],
                               evidence_receipt="repeat")
        next_state = p4b.evaluate(updated, self.diagnostics(), k=2, m=3)
        self.assertEqual(len(next_state["groups"][0]["remaining_strategies"]), 1)
        second = next_state["groups"][0]["remaining_strategies"][0]
        second_attempt = p4b.record_attempt(next_state, category=group["category"],
                                             group_key=group["group_key"],
                                             strategy_id=second["id"], evidence_receipt="callsite")
        exhausted = p4b.evaluate(second_attempt, self.diagnostics(), k=2, m=3)
        self.assertEqual(exhausted["status"], "exhausted_requires_evidence")
        self.assertFalse(exhausted["block_entire_run"])
    def test_new_fingerprint_same_count_not_false_improvement(self):
        first = p4b.evaluate({}, self.diagnostics(fingerprint="a"*64))
        second = p4b.evaluate(first, self.diagnostics(fingerprint="b"*64))
        self.assertEqual(second["nonprogress_batches"], 1)
    def test_optimized_checkpoint_does_not_time_stop(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder)
            with patch.dict(os.environ, {"SECURITY_CODE_REVIEW_EXECUTION_MODE": "optimized"}):
                with patch.object(review_log, "_clock", return_value=0.0):
                    review_log.start(target)
                    for _ in range(5):
                        review_log.checkpoint(target, "first_pass", {"completed_rules": 0})
                with patch.object(review_log, "_clock", return_value=1000.0):
                    current = review_log.checkpoint(target, "first_pass", {"completed_rules": 0})
            self.assertEqual(current["status"], "running")
            self.assertTrue(current["convergence"]["checkpoint_diagnostic_required"])
    def test_legacy_stall_unchanged(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder)
            with patch.dict(os.environ, {"SECURITY_CODE_REVIEW_EXECUTION_MODE": ""}):
                with patch.object(review_log, "_clock", return_value=0.0):
                    review_log.start(target)
                    for _ in range(5):
                        review_log.checkpoint(target, "first_pass", {"completed_rules": 0})
                with patch.object(review_log, "_clock", return_value=1000.0):
                    current = review_log.checkpoint(target, "first_pass", {"completed_rules": 0})
            self.assertEqual(current["status"], "stalled")

if __name__ == "__main__":
    unittest.main()
