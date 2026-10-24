"""P4：分類報告 Schema、隔離輸出、HTML/JSON 一致性與拒絕繞過測試。"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from partial_review import _atomic, _category_dir, initialize, read_category
from partial_report import (LIMITATIONS, _schema_validator, build_report, complete, html_errors,
                            render_partial_html, validate_saved, validation_errors)
from review_scope import CATEGORIES, ScopeError, load_catalog


def approved_safety(*args, **kwargs):
    return {
        "safety_valid": True, "first_pass_complete": True,
        "remaining_ids": [], "safety_integrity_errors": [],
        "second_pass": {"baseline_ready": True, "pending_count": 0, "pending_ids": []},
    }


class PartialReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = load_catalog()

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.source = self.root / "Tiny.cs"
        self.source.write_text("public class Tiny { public int Add(int a, int b) => a + b; }\n",
                               encoding="utf-8")
        self.report_root = self.root / "reports/security-code-review"
        self.report_root.mkdir(parents=True)
        self.formal = {name: self.report_root / name for name in
                       ("assessment.json", "report.json", "CodeReview_20261024.html")}
        for name, path in self.formal.items():
            path.write_text(f"FORMAL::{name}", encoding="utf-8")
        self.checkpoint = {name: path.read_bytes() for name, path in self.formal.items()}
        initialize(self.root, ("AC", "AU"), self.catalog)
        self._fill("AC")
        self._fill("AU")

    def _fill(self, category):
        original = read_category(self.root, category, self.catalog)
        for check in original["checks"]:
            check.update({
                "status": "na",
                "applicability_reason": "已閱讀來源及候選呼叫鏈，本測試專案沒有該分類安全控制責任。",
                "decision_reason": "已檢查所有候選來源及程式實作，確認測試類別中不直接適用。",
                "evidence": [], "reviewer": "review-tester",
                "execution": {"state": "completed", "methods": ["檢查完整來源與呼叫路徑"],
                              "summary": "已閱讀並分析測試專案全部原始碼與設定，完成此規則的真實適用性篩選。",
                              "inspected_paths": []},
            })
        original["file_reviews"] = [{
            "path": "Tiny.cs",
            "sha256": hashlib.sha256(self.source.read_bytes()).hexdigest(),
            "summary": "已實際閱讀 Tiny 類別的程式碼，這是單純加法實作，不含身份或審計控制。",
            "methods": ["全文閱讀及追查"],
            "category_screening": {category: {
                "rule_ids": [],
                "reason": "本檔只有簡單加法方法，無該類別的安全控制責任或對外授權操作"}},
            "rule_reviews": [],
            "candidate_exclusions": []
        }]
        _atomic(_category_dir(self.root, category) / "assessment.json", original)

    def _assert_formal_unmodified(self):
        for name, path in self.formal.items():
            self.assertEqual(path.read_bytes(), self.checkpoint[name])

    def test_partial_schemas_load_and_match_one_category(self):
        validator = _schema_validator()
        with patch("partial_report.validate_safety", side_effect=approved_safety):
            report = build_report(self.root, "AC", self.catalog)
        self.assertEqual(list(validator.iter_errors(report)), [])
        self.assertEqual(report["summary"]["total"], 8)
        self.assertEqual(report["summary"]["completed"], 8)
        self.assertEqual(report["review_mode"], "partial")
        self.assertEqual([r["id"] for r in report["rules"]], [f"AC-{i:02d}" for i in range(1, 9)])
        self.assertEqual(report["limitations"], LIMITATIONS)

    def test_two_categories_separate_reports_formal_untouched(self):
        with patch("partial_report.validate_safety", side_effect=approved_safety):
            output = complete(self.root, ("AC", "AU"), self.catalog)
            self.assertEqual(validate_saved(self.root, ("AC", "AU"), self.catalog), [])
        self.assertEqual(len(output), 2)
        self.assertEqual([o["rule_count"] for o in output], [8, 10])
        for category in ("AC", "AU"):
            folder = _category_dir(self.root, category)
            self.assertTrue((folder / "report.json").is_file())
            report = json.loads((folder / "report.json").read_text("utf-8"))
            self.assertTrue((folder / f"CodeReview_{report['project']['assessment_date'].replace('-', '')}.html").is_file())
            self.assertEqual(report["category"], category)
            self.assertTrue(all(check["id"].startswith(category + "-") for check in report["assessment"]["checks"]))
        self._assert_formal_unmodified()

    def test_unselected_category_does_not_write_results(self):
        with patch("partial_report.validate_safety", side_effect=approved_safety):
            complete(self.root, ("AC",), self.catalog)
        self.assertFalse((_category_dir(self.root, "AU") / "report.json").exists())
        self._assert_formal_unmodified()

    def test_live_safety_guard_denies_fake_completed_report(self):
        # 真實 P3 不接受為測試建立的全 NA/未複核證據。
        with self.assertRaises(ScopeError):
            complete(self.root, ("AC",), self.catalog)
        self.assertFalse((_category_dir(self.root, "AC") / "report.json").exists())
        self._assert_formal_unmodified()

    def test_multicategory_validation_precedes_writes(self):
        au_file = _category_dir(self.root, "AU") / "assessment.json"
        tampered = read_category(self.root, "AU", self.catalog)
        tampered["checks"][0]["execution"]["state"] = "pending"
        _atomic(au_file, tampered)
        with patch("partial_report.validate_safety", side_effect=approved_safety):
            with self.assertRaises(ScopeError):
                complete(self.root, ("AC", "AU"), self.catalog)
        self.assertFalse((_category_dir(self.root, "AC") / "report.json").exists())
        self._assert_formal_unmodified()

    def test_reject_tampered_summary_and_cross_category_check(self):
        with patch("partial_report.validate_safety", side_effect=approved_safety):
            data = build_report(self.root, "AC", self.catalog)
            data["summary"]["fail"] = 8
            self.assertTrue(validation_errors(data, self.root, "AC", self.catalog))
            data = build_report(self.root, "AC", self.catalog)
            data["rules"][0]["id"] = "AU-01"
            self.assertTrue(validation_errors(data, self.root, "AC", self.catalog))
        self._assert_formal_unmodified()

    def test_reject_removed_partial_disclaimer_and_forged_coverage(self):
        with patch("partial_report.validate_safety", side_effect=approved_safety):
            data = build_report(self.root, "AC", self.catalog)
            data["limitations"] = ["已完整審查所有類別並符合所有安全規範。"]
            self.assertTrue(validation_errors(data, self.root, "AC", self.catalog))
            data = build_report(self.root, "AC", self.catalog)
            data["source_coverage"]["source_file_count"] = 0
            self.assertTrue(validation_errors(data, self.root, "AC", self.catalog))

    def test_html_escapes_script_in_untrusted_rule_reason(self):
        with patch("partial_report.validate_safety", side_effect=approved_safety):
            data = build_report(self.root, "AC", self.catalog)
        poison = '<img src=x onerror=alert("bad")> </script>'
        data["assessment"]["checks"][0]["decision_reason"] = poison
        html = render_partial_html(data)
        self.assertNotIn('<img src=x onerror', html)
        self.assertNotIn("</script> </script>", html)
        self.assertIn("&lt;img", html)
        self.assertEqual(html_errors(html, data), [])

    def test_tampered_json_or_html_detected(self):
        with patch("partial_report.validate_safety", side_effect=approved_safety):
            complete(self.root, ("AC",), self.catalog)
            folder = _category_dir(self.root, "AC")
            report_file = folder / "report.json"
            data = json.loads(report_file.read_text("utf-8"))
            data["summary"]["pass"] = 8
            report_file.write_text(json.dumps(data), encoding="utf-8")
            self.assertNotEqual(validate_saved(self.root, ("AC",), self.catalog), [])
            report_file.write_text(json.dumps(build_report(self.root, "AC", self.catalog)), encoding="utf-8")
            html_file = next(folder.glob("CodeReview_*.html"))
            html_file.write_text(html_file.read_text("utf-8").replace("部分審查", "完整審查", 1), encoding="utf-8")
            self.assertNotEqual(validate_saved(self.root, ("AC",), self.catalog), [])
        self._assert_formal_unmodified()

    def test_source_changes_invalidate_saved_report_without_overwrite(self):
        with patch("partial_report.validate_safety", side_effect=approved_safety):
            complete(self.root, ("AC",), self.catalog)
        prior = (_category_dir(self.root, "AC") / "report.json").read_bytes()
        self.source.write_text("public class Tiny { public int Add(int a, int b) => 0; }\n", encoding="utf-8")
        with patch("partial_report.validate_safety", side_effect=approved_safety):
            self.assertTrue(validate_saved(self.root, ("AC",), self.catalog))
            with self.assertRaises(ScopeError):
                complete(self.root, ("AC",), self.catalog)
        self.assertEqual((_category_dir(self.root, "AC") / "report.json").read_bytes(), prior)
        self._assert_formal_unmodified()

    def test_formal_report_validator_does_not_accept_partial_json(self):
        with patch("partial_report.validate_safety", side_effect=approved_safety):
            complete(self.root, ("AC",), self.catalog)
        report = _category_dir(self.root, "AC") / "report.json"
        env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
        proc = subprocess.run([sys.executable, str(ROOT / "scripts/validate_report.py"),
                               "--report", str(report), "--source-root", str(self.root),
                               "--strict-sources"], text=True, encoding="utf-8",
                              capture_output=True, env=env, check=False)
        self.assertNotEqual(proc.returncode, 0)

    def test_category_cli_rejects_incomplete_without_touching_formal(self):
        env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
        proc = subprocess.run([
            sys.executable, str(ROOT / "scripts/complete_review.py"),
            "--target", str(self.root), "--categories", "AC,AU",
        ], text=True, encoding="utf-8", capture_output=True, env=env, check=False)
        self.assertNotEqual(proc.returncode, 0)
        self.assertFalse((_category_dir(self.root, "AC") / "report.json").exists())
        self._assert_formal_unmodified()

    def test_validate_report_category_cli_rejects_missing_partial(self):
        env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
        proc = subprocess.run([
            sys.executable, str(ROOT / "scripts/validate_report.py"),
            "--categories", "AC,AU", "--source-root", str(self.root), "--strict-sources",
        ], text=True, encoding="utf-8", capture_output=True, env=env, check=False)
        self.assertNotEqual(proc.returncode, 0)
        self._assert_formal_unmodified()

    def test_symlinked_partial_report_must_not_overwrite_formal(self):
        link = _category_dir(self.root, "AC") / "report.json"
        try:
            link.symlink_to(self.formal["report.json"])
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"無法建立 symbolic link：{exc}")
        with patch("partial_report.validate_safety", side_effect=approved_safety):
            with self.assertRaises(ScopeError):
                complete(self.root, ("AC",), self.catalog)
        self._assert_formal_unmodified()

    def test_explicit_all_ten_categories_remains_partial_contract(self):
        with patch("partial_report.validate_safety", side_effect=approved_safety):
            # 僅驗證分類契約，不寫入另外八份尚未初始化的工作資料。
            data = build_report(self.root, "AC", self.catalog)
        self.assertEqual(data["review_mode"], "partial")
        self.assertNotIn("formal_review", data)
        self._assert_formal_unmodified()


if __name__ == "__main__":
    unittest.main()
