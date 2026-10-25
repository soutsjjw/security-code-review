"""P0～P3：第一輪補正、證據歷史、完整性保護與唯讀診斷。"""
from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from partial_evidence_integrity import (
    FIRST_PASS_HISTORY, MANIFEST, PENDING, errors, recover, initialize as seal, commit,
)
from partial_review import _atomic, _category_dir, initialize, integrate, read_category, stage
from partial_review_safety import diagnose, validate
from review_scope import ScopeError, load_catalog


class FirstPassAmendmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = load_catalog()

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.source = self.root / "Safe.cs"
        self.source.write_text(
            "public class Safe { public bool Authorize() => false; }\n", encoding="utf-8")
        initialize(self.root, ("AC", "AU"), self.catalog)
        self.acdir = _category_dir(self.root, "AC")
        self.audir = _category_dir(self.root, "AU")
        self.assessment = read_category(self.root, "AC", self.catalog)
        self.original = copy.deepcopy(self.assessment["checks"][0])
        self.original["status"] = "pass"
        self.original["execution"]["state"] = "completed"
        self.original["decision_reason"] = "已完成初步程式碼判定，但仍需重新核對相關安全證據。"
        self.assessment["checks"][0] = self.original
        _atomic(self.acdir / "assessment.json", self.assessment)
        seal(self.root, "AC", explicit=True)
        seal(self.root, "AU")
        self.ausha = (self.audir / MANIFEST).read_bytes()

    def amendment(self, **values):
        evidence = {"path": "Safe.cs", "sha256": hashlib.sha256(self.source.read_bytes()).hexdigest(),
                    "line_start": 1, "line_end": 1, "excerpt": "public bool Authorize() => false;"}
        evidence.update(values)
        return {"AC-01": {
            "reason": "重新閱讀授權執行路徑並補查完整呼叫關係，確認原先控制證據記錄需要修正。",
            "source_evidence": [evidence],
        }}

    def correction(self, amendments=None):
        check = copy.deepcopy(self.original)
        check["decision_reason"] = "已追查入口至授權控制及拒絕分支，重新確認靜態控制實作。"
        return {"checks": [check],
                "first_pass_amendments": self.amendment() if amendments is None else amendments}

    def write_stage(self, payload):
        path = self.acdir / "payload.json"
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        with patch("partial_review.completion_errors", return_value=[]), \\
             patch("partial_review.decision_quality_errors", return_value=[]):
            stage(self.root, "AC", path, self.catalog)
        return path

    def integrate_amendment(self, payload, amend=True):
        self.write_stage(payload)
        with patch("partial_review.completion_errors", return_value=[]), \\
             patch("partial_review.decision_quality_errors", return_value=[]):
            return integrate(self.root, "AC", self.catalog, amend_first_pass=amend)

    def test_completed_rule_amended_with_historical_evidence_and_journal(self):
        previous_head = json.loads((self.acdir / MANIFEST).read_text("utf-8"))["head"]
        receipt = self.integrate_amendment(self.correction())
        self.assertEqual(receipt["first_pass_amended_rule_ids"], ["AC-01"])
        self.assertEqual(receipt["integrity_sequence"], 1)
        self.assertEqual(errors(self.root, "AC"), [])
        self.assertNotEqual(json.loads((self.acdir / MANIFEST).read_text("utf-8"))["head"],
                            previous_head)
        items = list((self.acdir / FIRST_PASS_HISTORY).glob("*.json"))
        self.assertEqual(len(items), 1)
        archive = json.loads(items[0].read_text("utf-8"))
        self.assertEqual(archive["previous_checks"]["AC-01"], self.original)
        self.assertEqual((self.audir / MANIFEST).read_bytes(), self.ausha)
        self.assertFalse((self.acdir / "analysis/first-pass-baseline.json").exists())

    def test_missing_explicit_flag_cannot_overwrite_completed(self):
        with self.assertRaisesRegex(ScopeError, "同時提供"):
            self.integrate_amendment(self.correction(), amend=False)
        self.assertEqual(read_category(self.root, "AC", self.catalog)["checks"][0], self.original)
        self.assertTrue((self.acdir / "analysis/staged/pending.json").exists())

    def test_flag_without_amendments_is_denied(self):
        payload = self.correction()
        del payload["first_pass_amendments"]
        with self.assertRaisesRegex(ScopeError, "同時提供"):
            self.integrate_amendment(payload)
        self.assertEqual(errors(self.root, "AC"), [])

    def test_wrong_source_hash_line_and_quote_denied(self):
        for override in ({"sha256": "0" * 64}, {"line_start": 2, "line_end": 2},
                         {"excerpt": "this code does not appear in source"}):
            with self.subTest(override=override):
                payload = self.correction(self.amendment(**override))
                self.write_stage(payload)
                with self.assertRaises(ScopeError):
                    integrate(self.root, "AC", self.catalog, amend_first_pass=True)
                (self.acdir / "analysis/staged/pending.json").unlink()
                self.assertEqual(errors(self.root, "AC"), [])

    def test_cannot_amend_after_baseline(self):
        commit(self.root, "AC", {"analysis/first-pass-baseline.json": {"checks": {}}},
               event="first-pass-baseline")
        with self.assertRaisesRegex(ScopeError, "baseline"):
            self.integrate_amendment(self.correction())

    def test_fail_cannot_be_demoted_or_lose_findings(self):
        # 以合法封存版本建立已確認 Fail（不直接修改受控檔案）。
        old = copy.deepcopy(self.original)
        old["status"] = "fail"
        old["finding_ids"] = ["F-01"]
        a = read_category(self.root, "AC", self.catalog)
        a["checks"][0] = old
        a["findings"] = [{"id": "F-01", "check_ids": ["AC-01"]}]
        commit(self.root, "AC", {"assessment.json": a}, event="verified-finding")
        self.original = old
        change = self.correction()
        change["checks"][0]["status"] = "pass"
        with self.assertRaisesRegex(ScopeError, "Fail"):
            self.integrate_amendment(change)

    def test_first_pass_fail_requires_linked_finding(self):
        payload = self.correction()
        payload["checks"][0]["status"] = "fail"
        payload["checks"][0]["finding_ids"] = ["missing"]
        with self.assertRaisesRegex(ScopeError, "Finding"):
            self.integrate_amendment(payload)

    def test_existing_file_review_and_control_record_can_be_repaired(self):
        first_review = {"path": "Safe.cs", "sha256": hashlib.sha256(self.source.read_bytes()).hexdigest(),
                        "summary": "舊版摘要", "methods": ["人工閱讀"],
                        "category_screening": {"AC": {"rule_ids": ["AC-01"], "reason": "授權入口"}},
                        "rule_reviews": [{"rule_id": "AC-01"}], "candidate_exclusions": []}
        a = read_category(self.root, "AC", self.catalog)
        a["file_reviews"] = [first_review]
        commit(self.root, "AC", {"assessment.json": a,
               "analysis/control-verifications.json": {"AC-01": {"status": "review"}}},
               event="prior-first-pass-record")
        fixed_review = copy.deepcopy(first_review)
        fixed_review["summary"] = "已重新確認此授權來源檔及控制入口，補充可追蹤的逐檔證據。"
        payload = {"file_reviews": [fixed_review],
                   "control_verifications": {"AC-01": {"status": "pass"}},
                   "first_pass_amendments": self.amendment()}
        r = self.integrate_amendment(payload)
        self.assertEqual(r["first_pass_amended_rule_ids"], ["AC-01"])
        self.assertEqual(read_category(self.root, "AC", self.catalog)["file_reviews"][0], fixed_review)
        self.assertEqual(errors(self.root, "AC"), [])

    def test_existing_file_with_unrelated_rules_cannot_be_rewritten(self):
        review = {"path": "Safe.cs", "sha256": hashlib.sha256(self.source.read_bytes()).hexdigest(),
                  "category_screening": {"AC": {"rule_ids": ["AC-02"], "reason": "相關"}},
                  "rule_reviews": [{"rule_id": "AC-02"}]}
        a = read_category(self.root, "AC", self.catalog)
        a["file_reviews"] = [review]
        commit(self.root, "AC", {"assessment.json": a}, event="prior-file")
        fixed = copy.deepcopy(review)
        fixed["summary"] = "試圖透過其他規則的證據改寫 AC-02"
        with self.assertRaises(ScopeError):
            self.integrate_amendment({"file_reviews": [fixed],
                                      "first_pass_amendments": self.amendment()})

    def test_interrupted_first_pass_archive_is_recoverable(self):
        from partial_evidence_integrity import _atomic as real_atomic
        def interrupted(path, value):
            if "first-pass-corrections" in str(path):
                raise OSError("模擬歷史寫入中斷")
            return real_atomic(path, value)
        self.write_stage(self.correction())
        with patch("partial_evidence_integrity._atomic", side_effect=interrupted), \\
             patch("partial_review.completion_errors", return_value=[]), \\
             patch("partial_review.decision_quality_errors", return_value=[]):
            with self.assertRaises(OSError):
                integrate(self.root, "AC", self.catalog, amend_first_pass=True)
        self.assertTrue((self.acdir / PENDING).is_file())
        self.assertTrue((self.acdir / "analysis/staged/pending.json").is_file())
        result = recover(self.root, "AC")
        self.assertTrue(result["recovered"])
        self.assertEqual(errors(self.root, "AC"), [])
        self.assertEqual(len(list((self.acdir / FIRST_PASS_HISTORY).glob("*.json"))), 1)

    def test_missing_manifest_is_not_bypassed_by_amendment(self):
        (self.acdir / MANIFEST).unlink()
        with self.assertRaises(ScopeError):
            self.integrate_amendment(self.correction())
        self.assertFalse((self.acdir / MANIFEST).exists())

    def test_diagnose_is_read_only_and_groups_results(self):
        before = (self.acdir / MANIFEST).read_bytes()
        result = diagnose(self.root, "AC", self.catalog)
        self.assertFalse(result["safety_valid"])
        self.assertGreater(result["integrity_error_count"], 0)
        self.assertEqual(sum(x["count"] for x in result["error_types"].values()),
                         result["integrity_error_count"])
        self.assertIn("source_coverage", result)
        self.assertEqual((self.acdir / MANIFEST).read_bytes(), before)
        self.assertFalse(validate(self.root, "AC", self.catalog)["safety_valid"])

    def test_cli_rejects_incompatible_first_pass_flags(self):
        program = str(ROOT / "scripts/review_queue.py")
        for args in (["--amend-first-pass"], ["--categories", "AC", "--integrate",
                                             "--amend-first-pass", "--allow-revision"]):
            p = subprocess.run([sys.executable, program, "--target", str(self.root), *args],
                               capture_output=True, text=True, encoding="utf-8")
            self.assertNotEqual(p.returncode, 0)
        p = subprocess.run([sys.executable, program, "--target", str(self.root),
                            "--categories", "AC,AU", "--diagnose"], capture_output=True,
                           text=True, encoding="utf-8")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(len(json.loads(p.stdout)["category_diagnostics"]), 2)


if __name__ == "__main__":
    unittest.main()
