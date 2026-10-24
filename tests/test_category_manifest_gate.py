"""分類 Manifest 缺失時的 fail-closed 與全新進度相容性驗收。"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from partial_evidence_integrity import (
    JOURNAL, MANIFEST, PENDING, STAGED, errors as sealed_errors,
    gate_errors, initialize as seal,
)
from partial_report import build_report, complete, validate_saved, validation_errors
from partial_review import _atomic, _category_dir, initialize, read_category, stage
from partial_review_safety import validate
from review_scope import ScopeError, load_catalog
import test_partial_report as fixture


class MissingManifestGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = load_catalog()
        fixture.PartialReportTests.setUpClass()

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        (self.root / "App.cs").write_text(
            "public sealed class App { public bool Check() => false; }\n",
            encoding="utf-8")
        official = self.root / "reports/security-code-review"
        official.mkdir(parents=True)
        self.formal = {
            name: official / name for name in ("assessment.json", "report.json",
                                                "CodeReview_20261024.html")
        }
        for name, path in self.formal.items():
            path.write_text("FORMAL:" + name, encoding="utf-8")
        self.before = {name: path.read_bytes() for name, path in self.formal.items()}
        initialize(self.root, ("AC", "AU"), self.catalog)

    def folder(self, category="AC"):
        return _category_dir(self.root, category)

    def formal_unchanged(self):
        self.assertEqual({name: path.read_bytes() for name, path in self.formal.items()},
                         self.before)

    def assert_denied(self, category="AC"):
        self.assertTrue(gate_errors(self.root, category))
        result = validate(self.root, category, self.catalog)
        self.assertFalse(result["safety_valid"])
        self.assertTrue(result["safety_integrity_errors"])
        self.assertIn("Manifest", " ".join(result["safety_integrity_errors"]))
        with patch("partial_report.validate_safety", side_effect=fixture.approved_safety):
            with self.assertRaises(ScopeError):
                build_report(self.root, category, self.catalog)
            with self.assertRaises(ScopeError):
                complete(self.root, (category,), self.catalog)
        self.assertFalse((self.folder(category) / "report.json").exists())
        self.formal_unchanged()

    def test_pristine_initialize_and_validation_keep_original_pending_workflow(self):
        self.assertFalse((self.folder() / MANIFEST).exists())
        self.assertEqual(gate_errors(self.root, "AC"), [])
        result = validate(self.root, "AC", self.catalog)
        self.assertFalse(result["safety_valid"])
        self.assertTrue(any("--prepare" in msg for msg in result["safety_integrity_errors"]))
        self.assertFalse(any("Manifest" in msg for msg in result["safety_integrity_errors"]))
        self.assertEqual(initialize(self.root, ("AC", "AU"), self.catalog), [])
        source = self.folder() / "batch.json"
        source.write_text('{"checks":[]}', encoding="utf-8")
        path = stage(self.root, "AC", source, self.catalog)
        self.assertEqual(path, self.folder() / STAGED)
        self.assertTrue((self.folder() / MANIFEST).is_file())
        self.assertEqual(sealed_errors(self.root, "AC"), [])
        self.formal_unchanged()

    def test_still_uninitialized_classification_is_not_falsely_sealed(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, root)
        (root / "App.cs").write_text("public class App {}\n", encoding="utf-8")
        self.assertEqual(gate_errors(root, "AC"), [])
        self.assertTrue(gate_errors(root, "AC", require_seal=True))
        initialize(root, ("AC",), self.catalog)
        self.assertEqual(gate_errors(root, "AC"), [])

    def test_changed_pending_summary_or_unexpected_check_field_is_not_pristine(self):
        assessment = self.folder() / "assessment.json"
        old = read_category(self.root, "AC", self.catalog)
        old["checks"][0]["execution"]["summary"] = "手動修改但狀態仍為 pending"
        _atomic(assessment, old)
        self.assert_denied()

    def test_completed_rule_without_manifest_is_denied_even_when_safety_is_mocked(self):
        assessment = self.folder() / "assessment.json"
        data = read_category(self.root, "AC", self.catalog)
        data["checks"][0]["execution"]["state"] = "completed"
        _atomic(assessment, data)
        self.assert_denied()

    def test_findings_and_file_reviews_without_manifest_are_denied(self):
        for field, value in (
            ("findings", [{"id": "F-01", "check_ids": ["AC-01"]}]),
            ("file_reviews", [{"path": "App.cs", "summary": "unsealed evidence"}]),
        ):
            with self.subTest(field=field):
                assessment = self.folder() / "assessment.json"
                data = read_category(self.root, "AC", self.catalog)
                data[field] = value
                _atomic(assessment, data)
                self.assert_denied()
                data[field] = []
                _atomic(assessment, data)

    def test_safety_evidence_file_without_manifest_is_denied(self):
        evidence = self.folder() / "analysis/decision-audits.json"
        _atomic(evidence, {"AC-01": {"status": "review"}})
        self.assert_denied()

    def test_journal_directory_even_if_empty_is_not_fresh_state(self):
        journal = self.folder() / JOURNAL
        journal.mkdir(parents=True)
        self.assert_denied()

    def test_manifest_removed_after_seal_is_denied_in_all_report_paths(self):
        seal(self.root, "AC")
        path = self.folder() / MANIFEST
        path.unlink()
        self.assertTrue((self.folder() / JOURNAL / "00000000.json").is_file())
        self.assert_denied()
        with patch("partial_report.validate_safety", side_effect=fixture.approved_safety):
            self.assertTrue(validation_errors({}, self.root, "AC", self.catalog))
        self.assertTrue(validate_saved(self.root, ("AC",), self.catalog))
        self.assertFalse(path.exists())

    def test_missing_manifest_and_journal_with_completed_assessment_still_denied(self):
        data = read_category(self.root, "AC", self.catalog)
        data["checks"][0]["status"] = "pass"
        data["checks"][0]["execution"]["state"] = "completed"
        _atomic(self.folder() / "assessment.json", data)
        self.assert_denied()

    def test_broken_initialization_artifacts_cannot_be_treated_as_pristine(self):
        (self.folder() / "project.json").unlink()
        self.assert_denied()

    def test_manifest_removed_does_not_affect_another_sealed_category(self):
        seal(self.root, "AC")
        seal(self.root, "AU")
        (self.folder() / MANIFEST).unlink()
        self.assertTrue(gate_errors(self.root, "AC"))
        self.assertEqual(gate_errors(self.root, "AU"), [])
        self.assertEqual(sealed_errors(self.root, "AU"), [])
        self.formal_unchanged()

    def test_previously_generated_report_cannot_survive_manifest_deletion(self):
        # 用既有報告格式 fixture 驗證「已產出 HTML/JSON」後刪除 Manifest。
        local = fixture.PartialReportTests(
            methodName="test_two_categories_separate_reports_formal_untouched")
        local.setUp()
        self.addCleanup(local.doCleanups)
        with patch("partial_report.validate_safety", side_effect=fixture.approved_safety):
            output = complete(local.root, ("AC",), local.catalog)
            self.assertEqual(len(output), 1)
            self.assertEqual(validate_saved(local.root, ("AC",), local.catalog), [])
        (local.root / "reports/security-code-review/partial/AC/analysis/"
         "integrity-manifest.json").unlink()
        with patch("partial_report.validate_safety", side_effect=fixture.approved_safety):
            issues = validate_saved(local.root, ("AC",), local.catalog)
            self.assertTrue(issues)
            self.assertTrue(any("Manifest" in issue for issue in issues))
            with self.assertRaises(ScopeError):
                complete(local.root, ("AC",), local.catalog)
        self.assertTrue(Path(output[0]["report_path"]).is_file())
        for name, path in local.formal.items():
            self.assertEqual(path.read_bytes(), local.checkpoint[name])


if __name__ == "__main__":
    unittest.main()
