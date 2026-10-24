"""品質驗收測試只使用合成審查工件來測試守門，不代表 Agent 真實準確率。"""
from __future__ import annotations

import contextlib
import copy
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from quality_baseline import load_catalog, materialize
from quality_acceptance import (catalog_sha256, compare_runs, main, measure,
                                token_usage, verify_case_sources, verify_review)

REPORT = Path("reports/security-code-review")


class QualityAcceptanceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / "fixtures"
        self.catalog = load_catalog()
        materialize(self.root, self.catalog)
        self.cases = self.catalog["cases"]

    def _create_artifacts(self, case, *, completed=True):
        folder = self.root / case["id"] / REPORT
        folder.mkdir(parents=True, exist_ok=True)
        anchor = case["anchor"]
        line = next(n for n, source in enumerate(
            case["files"][anchor["path"]].splitlines(), 1) if anchor["text"] in source)
        check = {
            "id": case["rule_id"], "status": case["expected_status"],
            "finding_ids": ["F-001"] if case["expected_finding"] else [],
            "decision_reason": ("已分析原始碼；待確認：" + case["external_artifact"]
                                if case["expected_status"] == "review" else "原始碼確認"),
            "evidence": [{"kind": "source", "path": anchor["path"],
                          "line_start": line, "line_end": line}],
            "execution": {"state": "completed" if completed else "pending",
                          "inspected_paths": case["required_paths"]},
        }
        # 此測資只是模擬完整格式；正式判定真實性由 production queue 守門。
        checks = [check]
        for n in range(69):
            checks.append({"id": f"TEST-{n:02d}",
                           "status": "na", "execution": {"state": "completed"}})
        assessment = {
            "assessment_date": "2026-10-24", "checks": checks,
            "findings": ([{"id": "F-001", "check_ids": [case["rule_id"]]}]
                         if case["expected_finding"] else []),
        }
        (folder / "assessment.json").write_text(json.dumps(assessment), encoding="utf-8")
        (folder / "report.json").write_text("{}\n", encoding="utf-8")
        (folder / "CodeReview_20261024.html").write_text("<!doctype html>", encoding="utf-8")
        return folder, check

    def _complete_workspace(self):
        for case in self.cases:
            self._create_artifacts(case)

    def _mock_ready_queue(self, *args, **kwargs):
        return {"ready_for_report": True, "second_pass": {"pending_count": 0}}

    def test_source_files_must_match_original_bytes_and_reject_extra_code(self):
        case = self.cases[0]
        location = self.root / case["id"]
        self.assertEqual(verify_case_sources(case, location), [])
        f = location / case["anchor"]["path"]
        original = f.read_bytes()
        f.write_bytes(original + b"\n// attacker changed this")
        self.assertIn("與固定案例原始碼不同", str(verify_case_sources(case, location)))
        f.write_bytes(original)
        (location / "HiddenController.cs").write_text("class Bypass {}")
        self.assertIn("額外來源", str(verify_case_sources(case, location)))

    def test_missing_assessments_are_not_counted_as_agent_passes(self):
        with patch("quality_acceptance.build_queue", side_effect=self._mock_ready_queue):
            result = measure(self.root)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["verified_case_count"], 0)
        self.assertEqual(result["score"]["missed_fail"], 7)
        self.assertFalse(result["quality_gate_passed"])
        self.assertIsNone(result["token_usage"])

    def test_incomplete_or_tampered_work_is_blocked_even_if_expected_status_is_present(self):
        case = self.cases[0]
        folder, check = self._create_artifacts(case)
        with patch("quality_acceptance.build_queue", side_effect=self._mock_ready_queue):
            prediction, problems = verify_review(case, self.root / case["id"], [])
            self.assertEqual(problems, [])
            self.assertEqual(prediction["status"], case["expected_status"])
            check["execution"]["state"] = "pending"
            data = json.loads((folder / "assessment.json").read_text("utf-8"))
            data["checks"][0] = check
            (folder / "assessment.json").write_text(json.dumps(data), encoding="utf-8")
            prediction, problems = verify_review(case, self.root / case["id"], [])
            self.assertIsNone(prediction)
            self.assertIn("70 項規則尚未全部", str(problems))
            check["execution"]["state"] = "completed"
            data["checks"][0] = check
            (folder / "assessment.json").write_text(json.dumps(data), encoding="utf-8")
            (folder / "report.json").unlink()
            prediction, problems = verify_review(case, self.root / case["id"], [])
            self.assertIsNone(prediction)
            self.assertIn("正式 report.json", str(problems))

    def test_only_real_safety_queue_can_validate_complete_project(self):
        case = self.cases[0]
        self._create_artifacts(case)
        with patch("quality_acceptance.build_queue", return_value={
                "ready_for_report": False,
                "rule_integrity_errors": ["AC-01: 缺少控制來源證據"],
                "second_pass": {"pending_count": 1}}):
            prediction, problems = verify_review(case, self.root / case["id"], [])
            self.assertIsNone(prediction)
            self.assertIn("完整性守門尚未全部通過", str(problems))
            self.assertIn("第二輪反向複核尚未完成", str(problems))

    def test_all_synthetic_artifacts_evaluate_only_as_fixture_validation(self):
        self._complete_workspace()
        with patch("quality_acceptance.build_queue", side_effect=self._mock_ready_queue):
            result = measure(self.root)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["verified_case_count"], 16)
        self.assertEqual(result["score"]["passed_count"], 16)
        self.assertEqual(result["score"]["missed_fail"], 0)
        self.assertEqual(result["score"]["false_positive_fail"], 0)
        self.assertEqual(result["catalog_sha256"], catalog_sha256())
        self.assertEqual(result["measurement_source"], "review_artifacts")
        self.assertIn("無法獨立證明", result["trust_limit"])

    def test_cross_version_comparison_fails_if_single_passed_case_regresses(self):
        self._complete_workspace()
        with patch("quality_acceptance.build_queue", side_effect=self._mock_ready_queue):
            previous = measure(self.root)
            case = self.cases[0]
            folder = self.root / case["id"] / REPORT
            assessment = json.loads((folder / "assessment.json").read_text("utf-8"))
            assessment["checks"][0]["status"] = "fail"
            assessment["checks"][0]["finding_ids"] = ["F-001"]
            assessment["findings"] = [{"id": "F-001", "check_ids": [case["rule_id"]]}]
            (folder / "assessment.json").write_text(json.dumps(assessment), encoding="utf-8")
            current = measure(self.root, previous=previous)
        self.assertFalse(current["quality_gate_passed"])
        self.assertEqual(current["score"]["false_positive_fail"], 1)
        self.assertTrue(any("false_positive_fail" in x for x in current["regressions"]))
        self.assertTrue(any(case["id"] in x for x in current["regressions"]))

    def test_cannot_compare_different_catalogs_or_synthetic_p0_scores(self):
        self._complete_workspace()
        with patch("quality_acceptance.build_queue", side_effect=self._mock_ready_queue):
            current = measure(self.root)
        for change in ("source", "catalog", "cases"):
            with self.subTest(change=change):
                previous = copy.deepcopy(current)
                if change == "source":
                    previous["measurement_source"] = "synthetic_predictions"
                elif change == "catalog":
                    previous["catalog_sha256"] = "another"
                else:
                    previous["cases"] = previous["cases"][:1]
                with self.assertRaises(ValueError):
                    compare_runs(current, previous)

    def test_never_estimate_tokens_without_actual_executor_records(self):
        ids = [case["id"] for case in self.cases]
        self.assertIsNone(token_usage(self.root, ids, None))
        self.assertEqual(token_usage(self.root, ids, "review-1")["case_coverage"], 0)
        for cid in ids:
            path = self.root / cid / REPORT / "analysis/token-usage.jsonl"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({
                "run_id": "review-1", "executor": "codex", "input_tokens": 100,
                "output_tokens": 40, "cached_input_tokens": 20,
            }) + "\n", encoding="utf-8")
        result = token_usage(self.root, ids, "review-1")
        self.assertTrue(result["complete"])
        self.assertEqual(result["total_tokens"], 2240)
        self.assertEqual(result["cached_input_tokens"], 320)
        self.assertEqual(result["source"], "executor_reported")
        path = self.root / ids[0] / REPORT / "analysis/token-usage.jsonl"
        path.write_text(json.dumps({
            "run_id": "review-1", "input_tokens": -1, "output_tokens": 1,
            "cached_input_tokens": 0,
        }), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Token 計數不合法"):
            token_usage(self.root, ids, "review-1")

    def test_cli_returns_failure_for_missing_agent_artifacts_and_writes_metrics(self):
        output = self.root.parent / "results.json"
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(["--workspace", str(self.root), "--output", str(output)])
        self.assertEqual(code, 1)
        saved = json.loads(output.read_text("utf-8"))
        self.assertFalse(saved["quality_gate_passed"])
        self.assertEqual(saved["verified_case_count"], 0)
        with contextlib.redirect_stderr(io.StringIO()):
            code = main(["--workspace", str(self.root.parent / "not-there")])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
