"""Read-only repair-task scheduling: precedence, coverage, dependencies and regression."""
import base64
import copy
import gzip
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from rule_repair_tasks import build_rule_repair_tasks, classify_repair_work


def block(message, *rules):
    return {"message": message, "rule_ids": list(rules), "category": "other"}


class RuleRepairTasksTests(unittest.TestCase):
    def test_specific_contract_precedence_and_unknown(self):
        cases = [
            ("AU-04: review 缺少具體可追溯的檢核證據（來源路徑與行號）", "P0"),
            ("AC-01: Q2 控制鏈節點[0] 缺少實際控制分支", "P1"),
            ("AC-02: Q2 跨檔控制鏈需要至少兩檔", "P1"),
            ("AC-01: 尚有 62 筆跨檔／組態候選未查證", "P1"),
            ("BC-02: 缺少 project 規則整合／控制責任結案紀錄", "P2"),
            ("AC-01: Q3 缺少與 fail 判定相符的控制有效性／繞過路徑證據", "P3"),
            ("IN-01: P2 缺少控制存在、有效性與繞過路徑的查核紀錄", "P3"),
            ("DP-01: P3 必須核對儲存庫來源與實際控制責任", "P4"),
            ("DP-01: P3 靜態結論缺少真實控制來源證據", "P4"),
            ("BC-03: 缺少具體檢核摘要（至少 15 字）", "P5"),
            ("AC-01: 無法判定的非預期錯誤", "unclassified"),
        ]
        for message, expected in cases:
            with self.subTest(message=message):
                self.assertEqual(classify_repair_work(message), expected)

    def test_grouped_tasks_dependency_coalescing_and_immutability(self):
        d = {"blocked_count": 6, "blocker_signature": "sig", "blockers": [
            block("AC-01: Q2 控制鏈節點[0]", "AC-01"),
            block("AC-01: Q2 跨檔控制鏈需要至少兩檔", "AC-01"),
            block("AC-01: Q3 缺少與 fail 判定相符的控制有效性／繞過路徑證據", "AC-01"),
            block("DP-01: review 缺少具體可追溯的檢核證據", "DP-01"),
            block("DP-01: P3 靜態結論缺少真實控制來源證據", "DP-01"),
            block("DP-01: 缺少 project 規則整合／控制責任結案紀錄", "DP-01"),
        ]}
        before = copy.deepcopy(d)
        p = build_rule_repair_tasks(d, rule_batch_size=1)
        self.assertEqual(before, d)
        self.assertTrue(p["read_only"])
        self.assertTrue(p["task_coverage"]["valid"])
        self.assertEqual(p["work_counts"]["P1"], 2)
        self.assertEqual(len(p["rule_repair_batches"]), 2)
        m = {x["task_id"]: x for x in p["rule_repair_tasks"]}
        self.assertEqual(m["AC-01:P1"]["blocker_indexes"], [0, 1])
        self.assertEqual(m["AC-01:P3"]["depends_on"], ["AC-01:P1"])
        self.assertEqual(m["DP-01:P4"]["depends_on"], ["DP-01:P0"])
        self.assertEqual(m["DP-01:P2"]["depends_on"], ["DP-01:P0"])
        self.assertEqual(p, build_rule_repair_tasks(d, rule_batch_size=1))

    def test_unknown_and_unowned_blockers_are_never_silently_dropped(self):
        d = {"blocked_count": 2, "blockers": [
            block("AC-01: 未知完整性缺口", "AC-01"),
            block("第一輪：未知全域錯誤"),
        ]}
        p = build_rule_repair_tasks(d)
        self.assertFalse(p["task_coverage"]["valid"])
        self.assertEqual(p["task_coverage"]["unclassified_indexes"], [0, 1])
        self.assertEqual(p["task_coverage"]["assigned_count"], 2)
        self.assertEqual(p["task_coverage"]["duplicate_indexes"], [])

    def test_mismatched_diagnostic_count_cannot_pass(self):
        p = build_rule_repair_tasks({"blocked_count": 10, "blockers": [
            block("BC-03: 缺少具體檢核摘要（至少 15 字）", "BC-03")
        ]})
        self.assertFalse(p["task_coverage"]["valid"])
        self.assertFalse(p["task_coverage"]["count_matches_diagnostic"])

    def test_multirule_remains_one_task_not_double_counted(self):
        p = build_rule_repair_tasks({"blocked_count": 1, "blockers": [
            block("AC-01: Q2 控制鏈不完整", "AC-01", "AC-02")
        ]})
        self.assertEqual(p["task_coverage"]["assigned_count"], 1)
        self.assertEqual(p["task_coverage"]["duplicate_indexes"], [])
        self.assertEqual(len(p["rule_repair_tasks"]), 1)
        self.assertEqual(p["unscoped_task_ids"], ["multi:AC-01,AC-02:P1"])

    def test_real_155_snapshot_regression(self):
        fixture = Path(__file__).resolve().parent / "fixtures" / "first_pass_155_snapshot.json.gz.b64"
        data = json.loads(gzip.decompress(base64.b64decode(fixture.read_bytes())))
        self.assertEqual(data["blocker_signature"],
                         "902cf1859a4df9415b6431f2eff70144de11d1072d5e0c031513e58bb62f95dd")
        plan = build_rule_repair_tasks(data)
        self.assertEqual(plan["work_counts"], {
            "P0": 9, "P1": 9, "P2": 67, "P3": 53,
            "P4": 8, "P5": 9, "unclassified": 0,
        })
        self.assertTrue(plan["task_coverage"]["valid"])
        self.assertEqual(plan["task_coverage"]["blocker_total"], 155)
        self.assertEqual(plan["task_coverage"]["affected_rule_count"], 70)
        self.assertEqual(len(plan["rule_repair_batches"]), 9)
        self.assertTrue(all(len(b["rule_ids"]) <= 8 for b in plan["rule_repair_batches"]))
        matrix = {row["rule_id"]: row["work_items"] for row in plan["rule_work_matrix"]}
        p2 = {r for r, w in matrix.items() if "P2" in w}
        p3 = {r for r, w in matrix.items() if "P3" in w}
        self.assertEqual((len(p2), len(p3), len(p2 & p3), len(p2 | p3)),
                         (67, 53, 50, 70))
        self.assertEqual(matrix["BC-03"], ["P2", "P5"])
        self.assertEqual(matrix["AC-01"], ["P1", "P3"])
        self.assertEqual(matrix["DP-01"], ["P0", "P2", "P3", "P4"])

    def test_batch_size_validation(self):
        for size in (0, 9, -1):
            with self.assertRaises(ValueError):
                build_rule_repair_tasks({"blockers": []}, rule_batch_size=size)


if __name__ == "__main__":
    unittest.main()
