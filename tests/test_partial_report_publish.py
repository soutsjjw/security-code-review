"""P5：多分類發布故障復原、重入與正式 70 項報告隔離。"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from partial_report import complete, validate_saved
from partial_report_publish import PublicationError, publish
from partial_review import _atomic, _category_dir
from review_scope import ScopeError
from test_partial_report import PartialReportTests, approved_safety


class PublicationAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        PartialReportTests.setUpClass()

    def setUp(self):
        self.fixture = PartialReportTests(methodName="test_two_categories_separate_reports_formal_untouched")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.catalog = self.fixture.catalog
        self.formal = self.fixture.formal
        self.original_formal = self.fixture.checkpoint
        self.categories = ("AC", "AU")

    def _publish(self):
        with patch("partial_report.validate_safety", side_effect=approved_safety):
            return complete(self.root, self.categories, self.catalog)

    def _saved(self):
        paths = {}
        for cat in self.categories:
            folder = _category_dir(self.root, cat)
            for path in [folder / "report.json", *folder.glob("CodeReview_*.html")]:
                if path.is_file():
                    paths[str(path)] = path.read_bytes()
        return paths

    def _formal_unchanged(self):
        for name, path in self.formal.items():
            self.assertEqual(path.read_bytes(), self.original_formal[name])

    def test_reentrant_publication_is_deterministic_and_cleans_staging(self):
        self._publish()
        before = self._saved()
        self._publish()
        self.assertEqual(self._saved(), before)
        with patch("partial_report.validate_safety", side_effect=approved_safety):
            self.assertEqual(validate_saved(self.root, self.categories, self.catalog), [])
        self.assertFalse(list((self.root / "reports/security-code-review/partial").rglob(".review-p5-*")))
        self.assertFalse((self.root / "reports/security-code-review/partial/.publish.lock").exists())
        self._formal_unchanged()

    def test_second_category_failure_rolls_back_all_previous_reports(self):
        self._publish()
        previous = self._saved()
        path = _category_dir(self.root, "AU") / "assessment.json"
        changed = json.loads(path.read_text("utf-8"))
        changed["checks"][0]["decision_reason"] += "補充重新閱讀及驗證本分類實作的結果。"
        _atomic(path, changed)
        from partial_report_publish import _replace as original_replace
        calls = 0

        def interrupt(source, dest):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise OSError("simulated crash during AU publication")
            return original_replace(source, dest)

        with patch("partial_report.validate_safety", side_effect=approved_safety), \
             patch("partial_report_publish._replace", side_effect=interrupt):
            with self.assertRaises(OSError):
                complete(self.root, self.categories, self.catalog)
        self.assertEqual(self._saved(), previous)
        self._formal_unchanged()
        self.assertFalse((self.root / "reports/security-code-review/partial/.publish.lock").exists())

    def test_publication_failure_without_prior_reports_leaves_none(self):
        from partial_report_publish import _replace as original_replace
        calls = 0

        def interrupt(source, dest):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("simulated HTML write failure")
            return original_replace(source, dest)

        with patch("partial_report.validate_safety", side_effect=approved_safety), \
             patch("partial_report_publish._replace", side_effect=interrupt):
            with self.assertRaises(OSError):
                complete(self.root, self.categories, self.catalog)
        self.assertEqual(self._saved(), {})
        self._formal_unchanged()

    def test_post_commit_validation_failure_restores_earlier_reports(self):
        self._publish()
        old = self._saved()
        destinations = [(_category_dir(self.root, "AC") / "report.json", '{"invalid":1}\n'),
                        (_category_dir(self.root, "AU") / "report.json", '{"invalid":2}\n')]
        with self.assertRaises(PublicationError):
            publish(self.root, destinations, validate=lambda: [],
                    verify_saved=lambda: ["post-commit digest mismatch"])
        self.assertEqual(self._saved(), old)
        self._formal_unchanged()

    def test_stale_lock_refuses_overwriting_and_is_not_removed_by_other_process(self):
        self._publish()
        old = self._saved()
        lock = self.root / "reports/security-code-review/partial/.publish.lock"
        lock.write_text("pid=unknown\n", encoding="utf-8")
        with patch("partial_report.validate_safety", side_effect=approved_safety):
            with self.assertRaises(PublicationError):
                complete(self.root, self.categories, self.catalog)
        self.assertTrue(lock.is_file())
        lock.unlink()
        self.assertEqual(self._saved(), old)
        self._formal_unchanged()

    def test_reject_destination_outside_category_or_duplicate(self):
        base = self.root / "reports/security-code-review"
        with self.assertRaises(PublicationError):
            publish(self.root, [(base / "report.json", "{}")], validate=lambda: [],
                    verify_saved=lambda: [])
        path = _category_dir(self.root, "AC") / "report.json"
        with self.assertRaises(PublicationError):
            publish(self.root, [(path, "{}"), (path, "{}")], validate=lambda: [],
                    verify_saved=lambda: [])
        self._formal_unchanged()

    def test_existing_untouched_category_on_partial_publication_error(self):
        self._publish()
        old = self._saved()
        ac = _category_dir(self.root, "AC") / "assessment.json"
        payload = json.loads(ac.read_text("utf-8"))
        payload["checks"][0]["execution"]["state"] = "pending"
        _atomic(ac, payload)
        with patch("partial_report.validate_safety", side_effect=approved_safety):
            with self.assertRaises(ScopeError):
                complete(self.root, self.categories, self.catalog)
        self.assertEqual(self._saved(), old)
        self._formal_unchanged()


if __name__ == "__main__":
    unittest.main()
