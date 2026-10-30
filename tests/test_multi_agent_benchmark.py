"""P3 detection-regression metric tests; no fabricated agent performance."""
import sys
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/lib"))
from multi_agent_benchmark import compare


class BenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.labels = {"cases": [
            {"id": "idor-unsafe", "vulnerable": True},
            {"id": "session-unsafe", "vulnerable": True},
            {"id": "owner-safe", "vulnerable": False},
            {"id": "session-safe", "vulnerable": False}]}
        self.single = {"detected": ["idor-unsafe", "owner-safe"], "tokens": 1000,
                       "elapsed_seconds": 40, "tokens_measured": True}
        self.multi = {"detected": ["idor-unsafe", "session-unsafe"],
                      "tokens": 1450, "elapsed_seconds": 25, "tokens_measured": True}

    def test_metric_comparison(self):
        m = compare(self.labels, self.single, self.multi)
        self.assertEqual(m["single"]["recall"], 0.5)
        self.assertEqual(m["single"]["false_positive_rate"], 0.5)
        self.assertEqual(m["multi"]["recall"], 1.0)
        self.assertTrue(m["recall_not_worse"])
        self.assertTrue(m["false_positive_rate_not_worse"])

    def test_missing_metrics_or_duplicate_reports_are_rejected(self):
        bad = dict(self.multi)
        bad["detected"] = ["idor-unsafe", "idor-unsafe"]
        with self.assertRaisesRegex(ValueError, "重複"):
            compare(self.labels, self.single, bad)
        bad["detected"] = ["not-labeled"]
        with self.assertRaises(ValueError):
            compare(self.labels, self.single, bad)


if __name__ == "__main__":
    unittest.main()
