"""逐檔規則適用性證據、防灌水及變更失效回歸測試。"""
import copy
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from file_review_integrity import verified_file_rule_reviews
from source_coverage import build_source_coverage
from review_fixture import make_file_review


class FileReviewIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "Auth.cs").write_text("// 追蹤使用者身份與授權\n", encoding="utf-8")
        (self.root / "Config.cs").write_text("// 服務組態與安全設定\n", encoding="utf-8")
        self.checks = [
            {"id": "AC-01", "execution": {"state": "completed", "inspected_paths": ["Auth.cs"]}},
            {"id": "AU-01", "execution": {"state": "completed", "inspected_paths": ["Auth.cs"]}},
        ]
        self.assessment = {
            "checks": self.checks,
            "file_reviews": [
                make_file_review(self.root, "Auth.cs", ("AC-01", "AU-01")),
                make_file_review(self.root, "Config.cs"),
            ],
        }

    def test_multirule_and_explicit_not_applicable_are_covered(self):
        coverage = build_source_coverage(self.assessment, self.root)
        self.assertEqual(coverage["reviewed_source_file_count"], 2)
        self.assertEqual(coverage["missing_source_file_count"], 0)
        self.assertEqual(coverage["review_integrity_errors"], [])
        self.assertEqual(coverage["reviewed_file_rule_ids"]["Auth.cs"], ["AC-01", "AU-01"])
        self.assertEqual(coverage["reviewed_file_rule_ids"]["Config.cs"], [])

    def test_legacy_paths_only_are_rejected(self):
        self.assessment.pop("file_reviews")
        coverage = build_source_coverage(self.assessment, self.root)
        self.assertEqual(coverage["reviewed_source_file_count"], 0)
        self.assertEqual(coverage["missing_source_file_count"], 2)
        self.assertIn("缺少 file_reviews", str(coverage["review_integrity_errors"]))

    def test_sha256_changed_after_review_invalidates_file(self):
        (self.root / "Auth.cs").write_text("// 來源內容遭到修改\n", encoding="utf-8")
        coverage = build_source_coverage(self.assessment, self.root)
        self.assertEqual(coverage["reviewed_source_file_count"], 1)
        self.assertIn("sha256", str(coverage["review_integrity_errors"]))

    def test_missing_category_invalidates_file(self):
        self.assessment["file_reviews"][0]["category_screening"].pop("SI")
        coverage = build_source_coverage(self.assessment, self.root)
        self.assertIn("10 類", str(coverage["review_integrity_errors"]))
        self.assertEqual(coverage["missing_source_file_count"], 1)

    def test_forged_rule_link_without_matching_review_is_rejected(self):
        self.checks.append({
            "id": "IN-01", "execution": {"state": "completed", "inspected_paths": ["Config.cs"]}
        })
        coverage = build_source_coverage(self.assessment, self.root)
        self.assertIn("未經逐檔驗證", str(coverage["review_integrity_errors"]))
        self.assertEqual(coverage["missing_source_file_count"], 0)
        # 即使文件都曾讀過，偽造的規則關聯仍須阻擋完整報告。
        self.assertTrue(coverage["review_integrity_errors"])

    def test_file_rule_not_in_completed_check_is_rejected(self):
        self.checks[1]["execution"]["state"] = "pending"
        result = build_source_coverage(self.assessment, self.root)
        self.assertIn("未同步登錄 completed", str(result["review_integrity_errors"]))
        self.assertIn("Auth.cs", result["missing_source_paths"])

    def test_line_numbers_must_be_real(self):
        self.assessment["file_reviews"][0]["rule_reviews"][0]["line_start"] = 700
        self.assessment["file_reviews"][0]["rule_reviews"][0]["line_end"] = 700
        result = build_source_coverage(self.assessment, self.root)
        self.assertIn("行號", str(result["review_integrity_errors"]))

    def test_rule_screening_cannot_disagree_with_rule_review(self):
        self.assessment["file_reviews"][0]["category_screening"]["AC"]["rule_ids"] = []
        result = build_source_coverage(self.assessment, self.root)
        self.assertIn("不一致", str(result["review_integrity_errors"]))

    def test_duplicate_review_not_double_counted(self):
        self.assessment["file_reviews"].append(copy.deepcopy(self.assessment["file_reviews"][0]))
        result = build_source_coverage(self.assessment, self.root)
        self.assertIn("重複路徑", str(result["review_integrity_errors"]))

    def test_reject_identical_reason_across_categories(self):
        row = self.assessment["file_reviews"][0]
        for category in ("EH", "LG", "DP"):
            row["category_screening"][category]["reason"] = (
                "已閱讀本檔內容；未見此檔直接實作該類控制，責任由其他元件承擔。"
            )
        coverage = build_source_coverage(self.assessment, self.root)
        self.assertIn("共用完全相同的理由", " ".join(coverage["review_integrity_errors"]))
        self.assertIn("Auth.cs", coverage["missing_source_paths"])

    def test_legitimate_single_applicable_rule_is_allowed(self):
        self.checks[1]["execution"]["inspected_paths"] = []
        self.assessment["file_reviews"][0] = make_file_review(self.root, "Auth.cs", ["AC-01"])
        coverage = build_source_coverage(self.assessment, self.root)
        self.assertEqual(coverage["review_integrity_errors"], [])
        self.assertEqual(coverage["reviewed_file_rule_ids"]["Auth.cs"], ["AC-01"])

    def test_mass_template_summaries_are_rejected(self):
        for i in range(40):
            path = f"Unit{i}.cs"
            (self.root / path).write_text("// sample " + str(i) + "\n", encoding="utf-8")
            row = make_file_review(self.root, path)
            row["summary"] = f"已逐行讀取 {i + 1} 行；依內容辨識並核對：一般組態的安全控制。"
            self.assessment["file_reviews"].append(row)
        coverage = build_source_coverage(self.assessment, self.root)
        self.assertIn("共用相同的逐檔摘要模板", " ".join(coverage["review_integrity_errors"]))

    def test_mass_template_with_variable_paths_and_rule_ids_is_rejected(self):
        for i in range(40):
            path = f"Unit{i:03}.cs"
            (self.root / path).write_text("// sample control\n", encoding="utf-8")
            row = make_file_review(self.root, path, ["AC-01"])
            row["summary"] = f"針對不同資料流的安全控制，本次驗證每個模組 Unit{i:03} 的檢核流程。"
            row["rule_reviews"][0]["reason"] = (
                f"{path} 第 1 行：已靜態追蹤 AC-01 相關實作；仍需部署、政策或動態佐證。"
            )
            self.assessment["file_reviews"].append(row)
            self.checks[0]["execution"]["inspected_paths"].append(path)
        coverage = build_source_coverage(self.assessment, self.root)
        self.assertIn("共用相同的逐檔規則結論模板", " ".join(coverage["review_integrity_errors"]))

    def test_no_evidence_is_synthesized_or_mutated(self):
        finding = {"id": "F-01", "title": "保留歷史弱點"}
        self.assessment["findings"] = [finding]
        original = copy.deepcopy(self.assessment)
        verified_file_rule_reviews(self.assessment, self.root, {"Auth.cs", "Config.cs"})
        self.assertEqual(self.assessment, original)

    def test_rule_level_fail_requires_finding(self):
        self.assessment["file_reviews"][0]["rule_reviews"][0]["result"] = "fail"
        self.checks[0]["status"] = "fail"
        result = build_source_coverage(self.assessment, self.root)
        self.assertIn("未建立 Finding", str(result["review_integrity_errors"]))

    def test_applicable_file_must_not_be_globally_na(self):
        self.checks[0]["status"] = "na"
        result = build_source_coverage(self.assessment, self.root)
        self.assertIn("標為 na", str(result["review_integrity_errors"]))

    def _na_scope_check(self):
        (self.root / "NoCommand.cs").write_text(
            "public static class Startup { public static int Add(int a, int b) => a + b; }\n",
            encoding="utf-8",
        )
        self.assessment["file_reviews"].append(
            make_file_review(self.root, "NoCommand.cs")
        )
        record = {
            "id": "IN-04",
            "status": "na",
            "applicability_reason": (
                "本專案未提供任何應用程式控制的作業系統命令執行入口，已確認所有責任來源。"
            ),
            "decision_reason": (
                "已搜尋 Process.Start、ProcessStartInfo 與 ShellExecute，"
                "實際閱讀入口與外部邊界，確認沒有從 HTTP 輸入流向作業系統命令的執行路徑。"
            ),
            "evidence": [{
                "kind": "source", "path": "NoCommand.cs", "line_start": 1,
                "line_end": 1, "description": "實際查核來源，只包含受控算術運算。",
            }],
            "execution": {
                "state": "completed",
                "inspected_paths": ["NoCommand.cs"],
                "methods": ["閱讀實際程式碼及搜尋命令執行呼叫點"],
                "summary": "已完成命令執行入口的靜態調查，未找到此類控制責任。",
            },
        }
        self.checks.append(record)
        return record

    def test_na_inspection_link_keeps_rule_nonapplicable(self):
        check = self._na_scope_check()
        frozen = copy.deepcopy(self.assessment)
        coverage = build_source_coverage(self.assessment, self.root)
        self.assertEqual(coverage["review_integrity_errors"], [])
        self.assertEqual(coverage["unverified_inspected_paths"]["total"], 0)
        self.assertEqual(coverage["verified_na_inspection_paths"], {"IN-04": ["NoCommand.cs"]})
        self.assertEqual(coverage["reviewed_file_rule_ids"]["NoCommand.cs"], [])
        self.assertEqual(self.assessment, frozen)
        self.assertEqual(check["status"], "na")

    def test_na_scope_without_located_evidence_must_remain_blocked(self):
        check = self._na_scope_check()
        check["evidence"] = []
        coverage = build_source_coverage(self.assessment, self.root)
        self.assertEqual(coverage["unverified_inspected_paths"]["total"], 1)
        self.assertEqual(coverage["verified_na_inspection_paths"], {})
        self.assertIn("未經逐檔驗證", " ".join(coverage["review_integrity_errors"]))

    def test_na_scope_with_invalid_file_hash_must_remain_blocked(self):
        self._na_scope_check()
        self.assessment["file_reviews"][-1]["sha256"] = "0" * 64
        coverage = build_source_coverage(self.assessment, self.root)
        self.assertEqual(coverage["unverified_inspected_paths"]["total"], 1)
        self.assertIn("NoCommand.cs", coverage["missing_source_paths"])

    def test_na_scope_cannot_be_recast_as_applicable_rule_review(self):
        self._na_scope_check()
        row = self.assessment["file_reviews"][-1]
        row["rule_reviews"].append({
            "rule_id": "IN-04", "result": "review",
            "reason": "模擬錯誤的 NA 規則轉為適用紀錄，這筆紀錄應當被正式驗證拒絕。",
            "line_start": 1, "line_end": 1,
        })
        row["category_screening"]["IN"]["rule_ids"] = ["IN-04"]
        coverage = build_source_coverage(self.assessment, self.root)
        self.assertIn("標為 na", " ".join(coverage["review_integrity_errors"]))

    def test_na_inspected_path_must_have_valid_file_review(self):
        check = self._na_scope_check()
        check["execution"]["inspected_paths"].append("Missing.cs")
        # Missing.cs is not an eligible source and cannot be used as evidence
        # of completeness; source inventory and schema remain authoritative.
        coverage = build_source_coverage(self.assessment, self.root)
        self.assertNotIn("Missing.cs", coverage["verified_na_inspection_paths"]["IN-04"])

    def test_file_fail_conflicts_with_global_pass(self):
        self.assessment["file_reviews"][0]["rule_reviews"][0]["result"] = "fail"
        self.checks[0]["status"] = "pass"
        self.assessment["findings"] = [{"id": "F1", "check_ids": ["AC-01"]}]
        result = build_source_coverage(self.assessment, self.root)
        self.assertIn("標為 pass", str(result["review_integrity_errors"]))


    def test_orphaned_link_summary_is_rule_scoped_and_read_only(self):
        self.checks.append({
            "id": "IN-01",
            "execution": {"state": "completed", "inspected_paths": ["Config.cs"]},
        })
        original = copy.deepcopy(self.assessment)
        coverage = build_source_coverage(self.assessment, self.root)
        gaps = coverage["unverified_inspected_paths"]
        self.assertEqual(gaps["total"], 1)
        self.assertEqual(gaps["by_rule"], {"IN-01": 1})
        self.assertEqual(gaps["by_reason"], {"missing_rule_review": 1})
        self.assertFalse(gaps["verified"])
        self.assertEqual(self.assessment, original)
        self.checks.reverse()
        again = build_source_coverage(self.assessment, self.root)
        self.assertEqual(gaps["fingerprint"],
                         again["unverified_inspected_paths"]["fingerprint"])

    def test_invalid_file_record_is_not_a_valid_rule_link(self):
        self.assessment["file_reviews"][0]["category_screening"].pop("SI")
        gaps = build_source_coverage(self.assessment, self.root)["unverified_inspected_paths"]
        self.assertEqual(gaps["total"], 2)
        self.assertEqual(gaps["by_reason"], {"invalid_file_review": 2})



if __name__ == "__main__":
    unittest.main()
