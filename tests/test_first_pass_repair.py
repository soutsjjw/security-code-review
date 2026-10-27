"""P0–P3 定向修復方案與逐批守門的正反向測試。"""
import copy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from batch_evidence_gate import batch_quality_errors
from first_pass_repair import blocker_source_path, repair_plan


def file_review(path, reason="已審查真實的授權控制執行分支並核對來源與行號。", rule="AC-08"):
    return {"path": path, "rule_reviews": [{"rule_id": rule, "reason": reason}]}


class RepairPlanTests(unittest.TestCase):
    def test_priority_and_immutability(self):
        rows = [
            file_review(f"src/Handler{i}.cs",
                        f"已讀取 src/Handler{i}.cs 實際第 {i} 行並將其與 LG-01 的正式檢核結果交叉核對；本檔證據未脫離全專案判定。",
                        "LG-01")
            for i in range(20)
        ]
        assessment = {
            "checks": [{"id": "LG-01", "execution": {"state": "completed",
                        "inspected_paths": [r["path"] for r in rows]}}],
            "file_reviews": rows,
            "findings": [{"id": "LG-01-F1", "check_ids": ["LG-01"]}],
        }
        diagnostics = {"ready_for_second_pass": False, "blocked_count": 3,
                       "blocker_signature": "fixed-signature", "blockers": [
            {"category": "unrelated_evidence", "rule_ids": ["LG-01"],
             "message": "src/Handler0.cs: LG-01: unrelated evidence"},
            {"category": "control_trace", "rule_ids": ["LG-01"],
             "message": "LG-01: Q2 控制鏈與正式來源無交集"},
        ]}
        frozen = copy.deepcopy(assessment)
        plan = repair_plan(assessment, diagnostics, limit=3)
        self.assertEqual(assessment, frozen)
        self.assertEqual(plan["suspected_template_paths"], 20)
        self.assertEqual(plan["candidate_repair_file_count"], 20)
        self.assertEqual(len(plan["priority_files"]), 3)
        self.assertEqual(plan["priority_files"][0]["path"], "src/Handler0.cs")
        self.assertIn("LG-01", plan["p2_control_rules"])
        self.assertTrue(plan["read_only"])

    def test_source_blockers_are_mapped_by_both_authoritative_prefix_formats(self):
        path = "src/Orders/DeleteOrderCommandHandler.cs"
        assessment = {
            "checks": [{"id": "AC-08", "execution": {
                "state": "completed", "inspected_paths": [path]}}],
            "file_reviews": [file_review(path)],
        }
        diagnostics = {"blocked_count": 3, "ready_for_second_pass": False,
                       "blocker_signature": "same", "blockers": [
            {"category": "unrelated_evidence", "rule_ids": ["AC-08"],
             "message": "AC-08: src/Orders/DeleteOrderCommandHandler.cs:8-19 "
                        "引用程式碼與本規則的控制行為無關"},
            {"category": "unrelated_evidence", "rule_ids": ["AC-08"],
             "message": "src/Orders/DeleteOrderCommandHandler.cs: AC-08: "
                        "rule_reviews 只有宣告／無關程式碼"},
            {"category": "control_trace", "rule_ids": ["AC-01"],
             "message": "AC-01: Q2 控制鏈未連結正式證據"},
        ]}
        result = repair_plan(assessment, diagnostics)
        self.assertEqual(result["candidate_repair_file_count"], 1)
        self.assertEqual(result["priority_files"][0]["observed_source_blockers"],
                         {"unrelated_evidence": 2})
        self.assertEqual(result["priority_files"][0]["repair_order"], "P0 逐檔證據重讀")
        self.assertIsNone(blocker_source_path(
            "AC-08: src/Unknown.cs:8-19 來源錯誤", {path}
        ))

    def test_missing_rule_links_are_not_auto_removed(self):
        assessment = {"file_reviews": [file_review("src/Handler.cs")],
                      "checks": [{"id": "AC-01", "execution": {
                          "state": "completed", "inspected_paths": ["src/Handler.cs"]}}]}
        diag = {"blockers": [], "blocked_count": 1}
        out = repair_plan(assessment, diag)
        self.assertEqual(out["priority_files"][0]["missing_rule_review_ids"], ["AC-01"])
        self.assertEqual(assessment["checks"][0]["execution"]["inspected_paths"],
                         ["src/Handler.cs"])


class BatchGateTests(unittest.TestCase):
    def test_completed_file_rejects_authoritative_source_error(self):
        row = file_review("src/Handler.cs")
        before = {"file_reviews": [], "checks": []}
        after = {"file_reviews": [row],
                 "checks": [{"id": "AC-08", "execution": {
                     "state": "completed", "inspected_paths": ["src/Handler.cs"]}}]}
        with patch("file_review_integrity.verified_file_rule_reviews",
                   return_value=({}, ["src/Handler.cs: AC-08: 只有宣告／無關程式碼"])):
            problems = batch_quality_errors(Path("."), before, after,
                            changed_paths={"src/Handler.cs"}, snapshot_paths={"src/Handler.cs"})
        self.assertTrue(any("批次逐檔證據不合格" in x for x in problems))

    def test_missing_file_rule_link_is_rejected(self):
        before = {"file_reviews": [], "checks": []}
        after = {"file_reviews": [{"path": "src/Handler.cs", "rule_reviews": []}],
                 "checks": [{"id": "AC-08", "execution": {
                     "state": "completed", "inspected_paths": ["src/Handler.cs"]}}]}
        with patch("file_review_integrity.verified_file_rule_reviews", return_value=({}, [])):
            problems = batch_quality_errors(Path("."), before, after,
                         changed_paths={"src/Handler.cs"}, snapshot_paths={"src/Handler.cs"})
        self.assertIn("缺少 rule_reviews", " ".join(problems))

    def test_completed_na_inspection_skips_fake_rule_review_but_uses_full_gate(self):
        before = {"file_reviews": [], "checks": []}
        after = {"file_reviews": [{"path": "src/NoShell.cs", "rule_reviews": []}],
                 "checks": [{"id": "IN-04", "status": "na", "execution": {
                     "state": "completed", "inspected_paths": ["src/NoShell.cs"]}}]}
        with patch("file_review_integrity.verified_file_rule_reviews",
                   return_value=({"src/NoShell.cs": set()}, [])) as verifier, \
             patch("file_review_integrity.verified_na_inspection_links",
                   return_value={"src/NoShell.cs": {"IN-04"}}):
            problems = batch_quality_errors(
                Path("."), before, after,
                changed_paths={"src/NoShell.cs"}, snapshot_paths={"src/NoShell.cs"},
            )
        self.assertEqual(problems, [])
        verifier.assert_called_once()

    def test_completed_na_with_invalid_source_is_rejected(self):
        before = {"file_reviews": [], "checks": []}
        after = {"file_reviews": [{"path": "src/NoShell.cs", "rule_reviews": []}],
                 "checks": [{"id": "IN-04", "status": "na", "execution": {
                     "state": "completed", "inspected_paths": ["src/NoShell.cs"]}}]}
        with patch("file_review_integrity.verified_file_rule_reviews",
                   return_value=({"src/NoShell.cs": set()}, [
                       "存在 1 筆未經逐檔驗證的 inspected_paths"])) , \
             patch("file_review_integrity.verified_na_inspection_links", return_value={}):
            problems = batch_quality_errors(
                Path("."), before, after,
                changed_paths={"src/NoShell.cs"}, snapshot_paths={"src/NoShell.cs"},
            )
        self.assertIn("不適用檢查範圍缺少有效來源", " ".join(problems))

    def test_na_inspection_does_not_allow_other_statuses_without_reviews(self):
        before = {"file_reviews": [], "checks": []}
        after = {"file_reviews": [{"path": "src/NoShell.cs", "rule_reviews": []}],
                 "checks": [{"id": "IN-04", "status": "pass", "execution": {
                     "state": "completed", "inspected_paths": ["src/NoShell.cs"]}}]}
        with patch("file_review_integrity.verified_file_rule_reviews", return_value=({}, [])):
            problems = batch_quality_errors(
                Path("."), before, after,
                changed_paths={"src/NoShell.cs"}, snapshot_paths={"src/NoShell.cs"},
            )
        self.assertIn("缺少 rule_reviews", " ".join(problems))

    def test_new_mass_template_is_blocked_without_invalidating_unchanged_backlog(self):
        reason = "檢查了這個檔案的共同安全控制邏輯，確認各項來源位置。"
        original = [file_review(f"File{i}.cs", reason) for i in range(15)]
        before = {"file_reviews": original, "checks": []}
        after = {"file_reviews": original + [file_review("File15.cs", reason)], "checks": []}
        with patch("file_review_integrity.verified_file_rule_reviews", return_value=({}, [])):
            errors = batch_quality_errors(Path("."), before, after,
                              changed_paths={"File15.cs"}, snapshot_paths=set())
        self.assertIn("逐檔規則結論模板", " ".join(errors))
        unchanged = batch_quality_errors(Path("."), before, before,
                              changed_paths=set(), snapshot_paths=set())
        self.assertEqual(unchanged, [])

    def test_pending_rule_is_not_prematurely_treated_as_completed(self):
        row = file_review("src/Handler.cs")
        before = {"file_reviews": [], "checks": []}
        after = {"file_reviews": [row],
                 "checks": [{"id": "AC-08", "execution": {"state": "pending"}}]}
        with patch("file_review_integrity.verified_file_rule_reviews") as verifier:
            problems = batch_quality_errors(Path("."), before, after,
                              changed_paths={"src/Handler.cs"}, snapshot_paths={"src/Handler.cs"})
        self.assertEqual(problems, [])
        verifier.assert_not_called()


if __name__ == "__main__":
    unittest.main()
