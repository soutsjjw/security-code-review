"""P2 依根因整理既有 Blocker，不直接產生虛構的修復證據。"""
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts/lib"))
from review_blockers import summarize

class RootCauseGroupingTests(unittest.TestCase):
    def test_groups_by_category_with_rule_links(self):
        result=summarize([
            "AC-08: Q2 控制鏈缺少真實來源驗證",
            "AC-01: Q2 控制鏈尚未核對",
            "IN-01: 來源證據只含宣告不能證明控制",
        ])
        groups={g["category"]:g for g in result["root_cause_groups"]}
        self.assertEqual(groups["control_trace"]["blocker_count"],2)
        self.assertEqual(groups["control_trace"]["rule_ids"],["AC-01","AC-08"])
        self.assertEqual(groups["weak_source_evidence"]["blocker_count"],1)
        self.assertFalse(result["ready_for_second_pass"])
        self.assertIn("blocker_signature",result)

if __name__=="__main__":
    unittest.main()
