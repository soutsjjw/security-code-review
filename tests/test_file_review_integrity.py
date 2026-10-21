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

    def test_file_fail_conflicts_with_global_pass(self):
        self.assessment["file_reviews"][0]["rule_reviews"][0]["result"] = "fail"
        self.checks[0]["status"] = "pass"
        self.assessment["findings"] = [{"id": "F1", "check_ids": ["AC-01"]}]
        result = build_source_coverage(self.assessment, self.root)
        self.assertIn("標為 pass", str(result["review_integrity_errors"]))


if __name__ == "__main__":
    unittest.main()
