"""精簡佇列只減少上下文，不修改原有檢核執行狀態。"""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from review_queue import build_queue, load_rules


class CompactQueueTests(unittest.TestCase):
    def test_compact_is_shorter_but_preserves_progress(self):
        _, rules = load_rules()
        data = json.loads((ROOT / "examples/assessment.example.json").read_text("utf-8"))
        full = build_queue(data, rules, 5)
        compact = build_queue(data, rules, 5, compact=True)
        self.assertEqual([r["id"] for r in full["next_checks"]],
                         [r["id"] for r in compact["next_checks"]])
        self.assertEqual(full["ready_for_report"], compact["ready_for_report"])
        self.assertEqual(full["pending"], compact["pending"])
        self.assertGreater(len(json.dumps(full, ensure_ascii=False)),
                           2 * len(json.dumps(compact, ensure_ascii=False)))
        self.assertNotIn("web_guide_v32_checks", compact["next_checks"][0])
        self.assertNotIn("evidence", compact["next_checks"][0])

    def test_on_demand_rule_detail_and_invalid_id(self):
        _, rules = load_rules()
        data = json.loads((ROOT / "examples/assessment.example.json").read_text("utf-8"))
        detailed = build_queue(data, rules, 1, detail_id="CR-05")
        self.assertEqual([r["id"] for r in detailed["next_checks"]], ["CR-05"])
        self.assertEqual(len(detailed["next_checks"][0]["web_guide_v32_appendix3"]), 6)
        with self.assertRaises(ValueError):
            build_queue(data, rules, 1, detail_id="XX-99")


if __name__ == "__main__":
    unittest.main()
