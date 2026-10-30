"""Read-only repair-task scheduling: precedence, coverage, dependencies and regression."""
import base64
import copy
import gzip
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/lib"))
from rule_repair_tasks import (
    build_rule_repair_tasks, classify_repair_work,
    compare_rule_repair_diagnostics, _dependency_errors,
)


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
        self.assertEqual(p["unscoped_task_ids"], [])
        self.assertEqual(p["shared_rule_repair_batches"][0]["task_ids"], ["multi:AC-01,AC-02:P1"])
        self.assertTrue(p["task_coverage"]["valid"])
        self.assertEqual(p["task_coverage"]["unscheduled_task_ids"], [])

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
        self.assertEqual(plan["task_coverage"]["scheduled_task_count"],
                         plan["task_coverage"]["task_count"])
        self.assertEqual(plan["shared_rule_repair_batches"], [])
        self.assertTrue(all(len(b["rule_ids"]) <= 8 for b in plan["rule_repair_batches"]))
        matrix = {row["rule_id"]: row["work_items"] for row in plan["rule_work_matrix"]}
        p2 = {r for r, w in matrix.items() if "P2" in w}
        p3 = {r for r, w in matrix.items() if "P3" in w}
        self.assertEqual((len(p2), len(p3), len(p2 & p3), len(p2 | p3)),
                         (67, 53, 50, 70))
        self.assertEqual(matrix["BC-03"], ["P2", "P5"])
        self.assertEqual(matrix["AC-01"], ["P1", "P3"])
        self.assertEqual(matrix["DP-01"], ["P0", "P2", "P3", "P4"])

    def test_multi_rule_dependency_is_included_in_single_rule_task(self):
        d = {"blocked_count": 2, "blockers": [
            block("AC-01: Q2 控制鏈不完整", "AC-01", "AC-02"),
            block("AC-02: 缺少 project 規則整合／控制責任結案紀錄", "AC-02"),
        ]}
        p = build_rule_repair_tasks(d)
        by_id = {t["task_id"]: t for t in p["rule_repair_tasks"]}
        self.assertIn("multi:AC-01,AC-02:P1", by_id["AC-02:P2"]["depends_on"])
        self.assertTrue(p["task_coverage"]["valid"])

    def test_multiple_same_rule_prerequisite_tasks_are_not_overwritten(self):
        d = {"blocked_count": 3, "blockers": [
            block("AC-01: Q2 控制鏈不完整", "AC-01"),
            block("AC-01: Q2 控制鏈不完整（跨規則）", "AC-01", "AC-02"),
            block("AC-01: 缺少 project 規則整合／控制責任結案紀錄", "AC-01"),
        ]}
        p = build_rule_repair_tasks(d)
        by_id = {t["task_id"]: t for t in p["rule_repair_tasks"]}
        self.assertEqual(by_id["AC-01:P2"]["depends_on"],
                         ["AC-01:P1", "multi:AC-01,AC-02:P1"])

    def test_oversized_shared_scope_remains_unbatchable_and_invalid(self):
        rules = [f"AU-{i:02d}" for i in range(1, 10)]
        p = build_rule_repair_tasks({"blocked_count": 1, "blockers": [
            block("AU-01: Q2 控制鏈不完整", *rules),
        ]})
        self.assertFalse(p["task_coverage"]["valid"])
        self.assertEqual(p["task_coverage"]["scheduled_task_count"], 0)
        self.assertEqual(len(p["task_coverage"]["unscheduled_task_ids"]), 1)
        self.assertFalse(p["task_coverage"]["execution"]["valid"])
        self.assertEqual(len(p["task_coverage"]["execution"]["unscheduled_task_ids"]), 1)
        self.assertTrue(all(len(b["rule_ids"]) <= 8 for b in p["rule_repair_batches"]))

    def test_blocker_details_exactly_match_origin_diagnostics(self):
        d = {"blocked_count": 2, "blockers": [
            block("AC-01: Q2 控制鏈不完整", "AC-01"),
            block("AC-01: Q2 控制鏈節點[0]", "AC-01"),
        ]}
        p = build_rule_repair_tasks(d)
        task = p["rule_repair_tasks"][0]
        self.assertEqual(task["blocker_indexes"], [0, 1])
        self.assertEqual([x["message"] for x in task["blocker_details"]],
                         [b["message"] for b in d["blockers"]])

    def test_dependency_validator_detects_missing_edges_and_cycles(self):
        tasks = [
            {"task_id": "a", "depends_on": ["b"]},
            {"task_id": "b", "depends_on": ["a", "missing"]},
        ]
        errors = _dependency_errors(tasks)
        self.assertTrue(any(x.startswith("dependency_cycle:") for x in errors))
        self.assertIn("missing_dependency:b:missing", errors)

    def assert_execution_batches_safe(self, plan):
        batches = plan["execution_batches"]
        task_map = {task["task_id"]: task for task in plan["rule_repair_tasks"]}
        task_batch = {}
        batch_index = {batch["batch_id"]: index for index, batch in enumerate(batches)}
        for index, batch in enumerate(batches):
            self.assertLessEqual(len(batch["rule_ids"]), 8)
            self.assertEqual(batch["depends_on_batch_ids"],
                             sorted(batch["depends_on_batch_ids"],
                                    key=lambda bid: batch_index[bid]))
            for dep_batch in batch["depends_on_batch_ids"]:
                self.assertLess(batch_index[dep_batch], index)
            for task_id in batch["task_ids"]:
                self.assertNotIn(task_id, task_batch)
                task_batch[task_id] = batch["batch_id"]
                self.assertTrue(set(task_map[task_id]["rule_ids"]).issubset(
                    set(batch["rule_ids"])))
        for task_id, task in task_map.items():
            self.assertIn(task_id, task_batch)
            for dependency in task["depends_on"]:
                self.assertLess(batch_index[task_batch[dependency]],
                                batch_index[task_batch[task_id]])
                self.assertIn(task_batch[dependency],
                              batches[batch_index[task_batch[task_id]]]["depends_on_batch_ids"])
        for task in task_map.values():
            if task["priority"] != "P2":
                continue
            for related in task_map.values():
                if related["priority"] == "P3" and related["rule_ids"] == task["rule_ids"]:
                    self.assertEqual(task_batch[task["task_id"]],
                                     task_batch[related["task_id"]])
        self.assertTrue(plan["task_coverage"]["execution"]["valid"])

    def test_cross_rule_control_chain_precedes_dependent_rule_closure(self):
        diagnostic = {"blocked_count": 4, "blockers": [
            block("AC-01: Q2 控制鏈不完整", "AC-01", "AC-02"),
            block("AC-01: 缺少 project 規則整合／控制責任結案紀錄", "AC-01"),
            block("AC-01: Q3 缺少與 pass 判定相符的控制有效性／繞過路徑證據", "AC-01"),
            block("AC-02: 缺少 project 規則整合／控制責任結案紀錄", "AC-02"),
        ]}
        plan = build_rule_repair_tasks(diagnostic)
        self.assertTrue(plan["task_coverage"]["valid"])
        self.assert_execution_batches_safe(plan)
        positions = {task_id: i for i, b in enumerate(plan["execution_batches"])
                     for task_id in b["task_ids"]}
        self.assertLess(positions["multi:AC-01,AC-02:P1"], positions["AC-01:P2"])
        self.assertLess(positions["multi:AC-01,AC-02:P1"], positions["AC-02:P2"])
        self.assertEqual(positions["AC-01:P2"], positions["AC-01:P3"])

    def test_cross_rule_closure_waits_for_both_owners_source_prerequisites(self):
        diagnostic = {"blocked_count": 3, "blockers": [
            block("AC-01: review 缺少具體可追溯的檢核證據", "AC-01"),
            block("AC-02: Q2 控制鏈不完整", "AC-02"),
            block("AC-01: 缺少 project 規則整合／控制責任結案紀錄", "AC-01", "AC-02"),
        ]}
        plan = build_rule_repair_tasks(diagnostic)
        self.assert_execution_batches_safe(plan)
        by_id = {t["task_id"]: t for t in plan["rule_repair_tasks"]}
        self.assertEqual(by_id["multi:AC-01,AC-02:P2"]["depends_on"],
                         ["AC-01:P0", "AC-02:P1"])

    def test_overlapping_shared_control_and_single_rule_control_stay_together(self):
        diagnostic = {"blocked_count": 4, "blockers": [
            block("AC-01: Q2 控制鏈節點[0]", "AC-01", "AC-02"),
            block("AC-01: 缺少 project 規則整合／控制責任結案紀錄", "AC-01"),
            block("AC-01: Q3 缺少與 fail 判定相符的控制有效性／繞過路徑證據",
                  "AC-01", "AC-02"),
            block("AC-02: 缺少 project 規則整合／控制責任結案紀錄", "AC-02"),
        ]}
        plan = build_rule_repair_tasks(diagnostic)
        self.assert_execution_batches_safe(plan)
        batch_for = {task_id: batch["batch_id"] for batch in plan["execution_batches"]
                     for task_id in batch["task_ids"]}
        self.assertEqual(batch_for["AC-01:P2"],
                         batch_for["multi:AC-01,AC-02:P3"])
        self.assertEqual(batch_for["AC-02:P2"],
                         batch_for["multi:AC-01,AC-02:P3"])

    def test_transitively_shared_control_work_exceeding_rule_limit_fails_closed(self):
        blockers = [
            block(f"AU-{i:02d}: 缺少 project 規則整合／控制責任結案紀錄",
                  f"AU-{i:02d}", f"AU-{i + 1:02d}")
            for i in range(1, 9)
        ]
        plan = build_rule_repair_tasks({
            "blocked_count": len(blockers), "blockers": blockers
        })
        self.assertFalse(plan["task_coverage"]["execution"]["valid"])
        self.assertFalse(plan["task_coverage"]["valid"])
        self.assertTrue(plan["task_coverage"]["execution"]["unscheduled_task_ids"])

    def test_repair_plan_execution_order_deterministic_under_blocker_permutation(self):
        blockers = [
            block("AU-04: review 缺少具體可追溯的檢核證據", "AU-04"),
            block("AC-01: Q2 控制鏈不完整", "AC-01", "AC-02"),
            block("AU-04: 缺少 project 規則整合／控制責任結案紀錄", "AU-04"),
            block("AC-01: 缺少 project 規則整合／控制責任結案紀錄", "AC-01"),
            block("AC-01: Q3 缺少與 fail 判定相符的控制有效性／繞過路徑證據", "AC-01"),
            block("AC-01: P3 必須核對儲存庫來源與實際控制責任", "AC-01"),
        ]
        first = build_rule_repair_tasks({"blocked_count": len(blockers), "blockers": blockers})
        reversed_plan = build_rule_repair_tasks({
            "blocked_count": len(blockers), "blockers": list(reversed(blockers))
        })
        self.assert_execution_batches_safe(first)
        self.assert_execution_batches_safe(reversed_plan)
        self.assertEqual(first["execution_batches"], reversed_plan["execution_batches"])

    def test_original_155_snapshot_has_safe_execution_order(self):
        fixture = Path(__file__).resolve().parent / "fixtures" / "first_pass_155_snapshot.json.gz.b64"
        diagnostic = json.loads(gzip.decompress(base64.b64decode(fixture.read_bytes())))
        plan = build_rule_repair_tasks(diagnostic)
        self.assert_execution_batches_safe(plan)
        self.assertEqual(plan["task_coverage"]["execution"]["scheduled_task_count"],
                         len(plan["rule_repair_tasks"]))
        self.assertEqual(plan["task_coverage"]["execution"]["forward_dependency_edges"], [])

    def test_diagnostic_comparison_stops_on_new_categories_and_growth(self):
        b = {"blocker_signature": "old", "blockers": [
            {**block("BC-03: 缺少具體檢核摘要（至少 15 字）", "BC-03"),
             "category": "other"},
        ]}
        after = {"blocker_signature": "new", "blockers": [
            {**block(f"BC-0{i}: 缺少具體檢核摘要（至少 15 字）", f"BC-0{i}"),
             "category": "control_trace"} for i in range(2, 7)
        ]}
        result = compare_rule_repair_diagnostics(b, after)
        self.assertTrue(result["should_pause"])
        self.assertEqual(result["new_blocker_count"], 4)
        self.assertIn("control_trace", result["new_categories"])
        self.assertEqual(b["blocker_signature"], "old")

    def test_diagnostic_comparison_stops_on_integrity_or_unknown(self):
        previous = {"blockers": []}
        for message, category in [
            ("來源 Journal 校驗失敗", "integrity"),
            ("不認識的新格式", "other"),
        ]:
            result = compare_rule_repair_diagnostics(previous, {
                "blockers": [{**block(message, "BC-01"), "category": category}]})
            self.assertTrue(result["should_pause"])

    def test_diagnostic_comparison_detects_new_work_type_even_under_other(self):
        prior = {"blockers": [block("BC-02: 缺少具體檢核摘要（至少 15 字）", "BC-02")]}
        after = {"blockers": [
            block("BC-02: 缺少具體檢核摘要（至少 15 字）", "BC-02"),
            block("BC-02: 缺少 project 規則整合／控制責任結案紀錄", "BC-02"),
        ]}
        result = compare_rule_repair_diagnostics(prior, after)
        self.assertTrue(result["should_pause"])
        self.assertEqual(result["new_categories"], [])
        self.assertEqual(result["new_work_items"], ["P2"])

    def test_diagnostic_comparison_allows_reduced_known_blockers(self):
        prior = {"blockers": [block("BC-02: 缺少具體檢核摘要（至少 15 字）", "BC-02")]}
        result = compare_rule_repair_diagnostics(prior, {"blockers": []})
        self.assertFalse(result["should_pause"])
        self.assertEqual(result["removed_blocker_count"], 1)

    def test_batch_size_validation(self):
        for size in (0, 9, -1):
            with self.assertRaises(ValueError):
                build_rule_repair_tasks({"blockers": []}, rule_batch_size=size)


if __name__ == "__main__":
    unittest.main()
