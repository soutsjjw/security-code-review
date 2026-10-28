"""B0 真實來源標記與 P4-A 事件鏈安全回歸。"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from b0_baseline import observation, summary
from execution_boundary_events import append_violation, verify_run, batch_path, _verify_events

class B0Tests(unittest.TestCase):
    def test_unreported_token_is_unavailable(self):
        log = {"run_id": "r", "status": "running", "commands": 5,
               "progress": {"completed_rules": 70, "reviewed_files": 10, "second_pass_rules": 0},
               "phase_wall_seconds": {"queue": 100}, "command_seconds": {"integrate": 4},
               "token_usage": {"input_tokens": 0}}
        result = observation(log, "test.json")
        self.assertFalse(result["comparable"])
        self.assertEqual(result["metrics"]["input_tokens"]["source"], "unavailable")
        self.assertEqual(result["metrics"]["recorded_wall_seconds"]["value"], 100)
        self.assertEqual(summary([result])["runs"], 0)

    def test_median_only_uses_comparable_runs(self):
        log = {"run_id": "r", "status": "completed", "commands": 5}
        a = observation(log, "a", "a" * 40)
        log["commands"] = 7
        b = observation(log, "b", "a" * 40)
        c = observation(log, "c")
        result = summary([a, b, c])
        self.assertEqual(result["runs"], 2)
        self.assertEqual(result["metrics"]["commands"]["median"], 6)

class BoundaryEventsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.target = Path(self.temp.name)
        self.kwargs = dict(run_id="run-1", batch_id="batch-1", stage="first_pass",
                           boundary_level="L3", batch_fingerprint="a" * 64,
                           severity="warn", detection_method="filesystem-diff",
                           policy_id="unauthorized-executable")
    def test_append_and_validate_independent_batches(self):
        first = append_violation(self.target, **self.kwargs)
        second = append_violation(self.target, **self.kwargs)
        self.assertEqual(second["batch_sequence"], 2)
        self.assertEqual(second["previous_event_sha256"], first["event_sha256"])
        summary = verify_run(self.target, "run-1")
        self.assertEqual(summary["batches"][0]["status"], "no_block_events")
        other = dict(self.kwargs, batch_id="batch-2", severity="block")
        append_violation(self.target, **other)
        self.assertEqual(verify_run(self.target, "run-1")["blocked_batches"], ["batch-2"])
    def test_tampering_is_rejected(self):
        append_violation(self.target, **self.kwargs)
        p = batch_path(self.target, "run-1", "batch-1")
        rows = [json.loads(line) for line in p.read_text("utf-8").splitlines()]
        rows[0]["severity"] = "block"
        with self.assertRaises(Exception):
            _verify_events(rows, "run-1", "batch-1")
    def test_review_event_cannot_be_forged_by_untrusted_agent(self):
        first = append_violation(self.target, **dict(self.kwargs, severity="block"))
        review = dict(first, event_type="execution_boundary_review")
        with self.assertRaises(Exception):
            _verify_events([first, review], "run-1", "batch-1")
    def test_path_escape(self):
        with self.assertRaises(ValueError):
            batch_path(self.target, "run-1", "../escape")
    def test_unknown_schema_is_rejected(self):
        event = append_violation(self.target, **self.kwargs)
        event["schema_version"] = 2
        with self.assertRaises(Exception):
            _verify_events([event], "run-1", "batch-1")

if __name__ == "__main__":
    unittest.main()
