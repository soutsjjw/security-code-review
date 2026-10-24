"""完整／分類審查選擇與輸出路徑的唯讀契約測試。"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from review_scope import (CATEGORIES, CATEGORY_COUNTS, ScopeError, build_scope_plan,
                          load_catalog, parse_categories, validate_catalog)


class ReviewScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = load_catalog()

    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.target = Path(self.workspace.name)

    def plan(self, raw):
        return build_scope_plan(self.target, parse_categories(raw), self.catalog)

    def test_full_mode_retains_all_70_and_formal_output(self):
        result = self.plan(None)
        self.assertEqual(result["review_mode"], "full")
        self.assertEqual(result["selected_rule_count"], 70)
        self.assertEqual(len(result["selected_rule_ids"]), 70)
        self.assertEqual(result["selected_categories"], list(CATEGORIES))
        self.assertEqual(result["category_reports"], [])
        self.assertEqual(result["shared_analysis_dir"], "reports/security-code-review/analysis")
        self.assertTrue(result["plan_only"])

    def test_single_category_has_expected_ids_and_isolated_path(self):
        result = self.plan("AC")
        self.assertEqual(result["review_mode"], "partial")
        self.assertEqual(result["selected_rule_count"], 8)
        self.assertEqual(len(result["category_reports"]), 1)
        report = result["category_reports"][0]
        self.assertEqual(report["category"], "AC")
        self.assertEqual(report["rule_ids"], [f"AC-{i:02d}" for i in range(1, 9)])
        self.assertEqual(report["assessment_path"], "reports/security-code-review/partial/AC/assessment.json")
        self.assertEqual(report["analysis_dir"], "reports/security-code-review/partial/AC/analysis")

    def test_multiple_categories_keep_separate_reports_and_shared_index(self):
        result = self.plan(" au , ac ")
        self.assertEqual(result["selected_categories"], ["AC", "AU"])
        self.assertEqual(result["selected_rule_count"], 18)
        reports = result["category_reports"]
        self.assertEqual([r["category"] for r in reports], ["AC", "AU"])
        self.assertEqual([r["expected_rule_count"] for r in reports], [8, 10])
        self.assertNotEqual(reports[0]["report_dir"], reports[1]["report_dir"])
        self.assertEqual(result["shared_analysis_dir"], "reports/security-code-review/partial/_shared/analysis")
        self.assertTrue(all(r["report_dir"].startswith("reports/security-code-review/partial/") for r in reports))
        self.assertTrue(all(r["report_dir"] != result["formal_report_dir"] for r in reports))

    def test_other_categories_and_all_ten_remain_partial(self):
        result = self.plan("DP,PD,BC,SI")
        self.assertEqual(result["selected_rule_count"], 22)
        all_ten = self.plan(",".join(reversed(CATEGORIES)))
        self.assertEqual(all_ten["review_mode"], "partial")
        self.assertEqual(all_ten["selected_rule_count"], 70)
        self.assertEqual(len(all_ten["category_reports"]), 10)
        self.assertEqual(sum(CATEGORY_COUNTS.values()), 70)

    def test_bad_selection_fails_closed(self):
        for raw in ["", "  ", ",AC", "AC,", "AC,,AU", "AC,AC", "ac,AC", "AC,XX", "AC/../../AU"]:
            with self.subTest(raw=raw), self.assertRaises(ScopeError):
                parse_categories(raw)

    def test_bad_programmatic_selection_fails_closed(self):
        for categories in [(), ("AC", "AC"), ("XX",), ("AC/..",)]:
            with self.subTest(categories=categories), self.assertRaises(ScopeError):
                build_scope_plan(self.target, categories, self.catalog)

    def test_invalid_catalog_fails_closed(self):
        rules = list(self.catalog["rules"])
        for corrupt in [rules[:-1], rules[:-1] + [dict(rules[0])],
                        rules[:-1] + [dict(rules[-1], category="AC")]]:
            with self.subTest(corrupt=corrupt[-1].get("id")), self.assertRaises(ScopeError):
                validate_catalog({"rules": corrupt})

    def test_no_output_directories_or_existing_artifacts_changed(self):
        original = self.target / "reports/security-code-review/assessment.json"
        original.parent.mkdir(parents=True)
        original.write_text('{"keep":"original"}', encoding="utf-8")
        before = sorted(str(p.relative_to(self.target)) for p in self.target.rglob("*"))
        self.plan("AC,AU")
        self.assertEqual(original.read_text(encoding="utf-8"), '{"keep":"original"}')
        self.assertEqual(before, sorted(str(p.relative_to(self.target)) for p in self.target.rglob("*")))
        self.assertFalse((self.target / "reports/security-code-review/partial").exists())

    def test_cli_json_plan_and_invalid_input(self):
        script = ROOT / "scripts/review_scope.py"
        command = [sys.executable, str(script), "--target", str(self.target), "--categories", "AC,AU"]
        valid = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", check=False)
        self.assertEqual(valid.returncode, 0, valid.stderr)
        self.assertEqual(json.loads(valid.stdout)["selected_rule_count"], 18)
        invalid = subprocess.run([*command[:-1], "AC,INVALID"], capture_output=True,
                                 text=True, encoding="utf-8", check=False)
        self.assertNotEqual(invalid.returncode, 0)
        self.assertIn("未知分類", invalid.stderr)
        self.assertFalse((self.target / "reports").exists())

    def test_missing_target_rejected(self):
        with self.assertRaises(ScopeError):
            build_scope_plan(self.target / "missing", ("AC",), self.catalog)


if __name__ == "__main__":
    unittest.main()
