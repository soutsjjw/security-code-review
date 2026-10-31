"""P0 人工核定正確性案例與比對工具的回歸測試（不模擬 Agent 審查成功）。"""
from __future__ import annotations

import contextlib
import copy
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


def run_utf8_process(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    """解碼 dotnet 輸出不依賴 Windows ACP/CP950，保留錯誤訊息供診斷。"""
    return subprocess.run(command, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", check=False, **kwargs)


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/lib"))

from analysis_adapters import ModernDotNetAdapter
from quality_baseline import (assessment_predictions, evaluate, load_catalog, main,
                              materialize)


class QualityBaselineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = load_catalog()

    def make_perfect_predictions(self):
        """合成的對照輸入，只測量評分器；不可當成真實掃描結果。"""
        rows = []
        for case in self.catalog["cases"]:
            anchor = case["anchor"]
            line = next(
                i for i, source_line in enumerate(case["files"][anchor["path"]].splitlines(), 1)
                if anchor["text"] in source_line
            )
            rows.append({
                "case_id": case["id"], "status": case["expected_status"],
                "finding": case["expected_finding"],
                "decision_reason": ("已完成程式碼查核；待確認：" + case["external_artifact"]
                                    if case["expected_status"] == "review" else "已核對安全控制"),
                "inspected_paths": case["required_paths"].copy(),
                "evidence": [{"path": anchor["path"], "line_start": line, "line_end": line}],
            })
        return {"cases": rows}

    def test_catalog_has_balanced_known_answers_and_external_boundaries(self):
        cases = self.catalog["cases"]
        self.assertEqual(len(cases), 16)
        self.assertEqual(sum(c["expected_status"] == "pass" for c in cases), 7)
        self.assertEqual(sum(c["expected_status"] == "fail" for c in cases), 7)
        self.assertEqual(sum(c["expected_status"] == "review" for c in cases), 2)
        self.assertEqual(len({c["id"] for c in cases}), len(cases))
        grouped = {}
        for case in cases:
            grouped.setdefault(case["family"], set()).add(case["expected_status"])
        self.assertEqual(sum(statuses == {"pass", "fail"} for statuses in grouped.values()), 7)
        self.assertEqual(sum(statuses == {"review"} for statuses in grouped.values()), 2)
        self.assertTrue(all(c.get("external_artifact") for c in cases if c["expected_status"] == "review"))

    def test_catalog_rejects_unsafe_paths_unknown_rules_and_fake_anchors(self):
        for mutation in ("path", "rule", "anchor", "duplicate", "missing_artifact"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp:
                catalog = copy.deepcopy(self.catalog)
                first = catalog["cases"][0]
                if mutation == "path":
                    first["files"]["../outside.cs"] = "public class Exfil {}"
                elif mutation == "rule":
                    first["rule_id"] = "AC-99"
                elif mutation == "anchor":
                    first["anchor"]["text"] = "this line does not exist"
                elif mutation == "duplicate":
                    catalog["cases"].append(copy.deepcopy(first))
                elif mutation == "missing_artifact":
                    review = next(x for x in catalog["cases"] if x["expected_status"] == "review")
                    del review["external_artifact"]
                path = Path(temp) / "cases.json"
                path.write_text(json.dumps(catalog, ensure_ascii=False), encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_catalog(path)

    def test_missing_catalog_explains_upload_zip_has_no_fixtures(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "上傳用 Zip"):
                load_catalog(Path(temp) / "cases.json")

    def test_materialized_case_projects_are_isolated_and_supported(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "isolated"
            result = materialize(root, self.catalog)
            self.assertEqual(result["case_count"], 16)
            adapter = ModernDotNetAdapter()
            for case in self.catalog["cases"]:
                with self.subTest(case=case["id"]):
                    project = root / case["id"]
                    self.assertTrue(adapter.detect(project)["supported"])
                    self.assertEqual((project / "Case.csproj").read_text("utf-8").count("net8.0"), 1)
                    self.assertEqual({p.relative_to(project).as_posix() for p in project.rglob("*") if p.is_file()},
                                     {"Case.csproj", *case["files"].keys()})
            with self.assertRaisesRegex(ValueError, "不是空的"):
                materialize(root, self.catalog)

    def test_dotnet_output_decoding_is_independent_of_windows_cp950(self):
        """模擬不合法於 CP950/UTF-8 的輸出位元組，避免 subprocess reader thread 中止。"""
        code = ("import sys; "
                "sys.stdout.buffer.write(bytes([0xa3]) + '中文'.encode('utf-8')); "
                "sys.stderr.buffer.write(bytes([0xff]))")
        result = run_utf8_process([sys.executable, "-c", code])
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "\ufffd中文")
        self.assertEqual(result.stderr, "\ufffd")

    def test_fixtures_compile_with_dotnet8_when_available(self):
        """編譯只是語法健全性檢查，不表示任何案例已通過資安審查。"""
        dotnet = shutil.which("dotnet")
        if not dotnet:
            self.skipTest("dotnet CLI not installed")
        versions = run_utf8_process([dotnet, "--list-sdks"])
        if versions.returncode or not any(line.startswith("8.") for line in (versions.stdout or "").splitlines()):
            self.skipTest("net8.0 targeting SDK not available")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "projects"
            materialize(root, self.catalog)
            for case in self.catalog["cases"]:
                with self.subTest(case=case["id"]):
                    project = root / case["id"]
                    result = run_utf8_process(
                        [dotnet, "build", "Case.csproj", "--nologo", "--ignore-failed-sources"],
                        cwd=project, timeout=120,
                    )
                    self.assertEqual(result.returncode, 0,
                                     f"{case['id']} 編譯失敗:\\n{(result.stdout or '')[-1800:]}\\n{(result.stderr or '')[-1200:]}")

    def test_scoring_measures_expected_status_finding_trace_and_evidence(self):
        result = evaluate(self.catalog, self.make_perfect_predictions())
        self.assertTrue(result["all_passed"])
        self.assertEqual(result["status_accuracy"], 1)
        self.assertEqual(result["fail_recall"], 1)
        self.assertEqual(result["fail_precision"], 1)
        self.assertEqual(result["review_correct"], 2)
        self.assertEqual(result["review_gap_specific_count"], 2)
        self.assertEqual(result["trace_complete_count"], 16)
        self.assertEqual(result["evidence_valid_count"], 16)
        self.assertEqual(result["passed_count"], 16)

    def test_missed_vulnerability_and_false_positive_are_reported_separately(self):
        predictions = self.make_perfect_predictions()
        missed = next(x for x in predictions["cases"] if x["case_id"] == "idor-missing-owner-check")
        missed["status"], missed["finding"] = "pass", False
        wrong = next(x for x in predictions["cases"] if x["case_id"] == "sql-parameterized")
        wrong["status"], wrong["finding"] = "fail", True
        score = evaluate(self.catalog, predictions)
        self.assertEqual(score["missed_fail"], 1)
        self.assertEqual(score["false_positive_fail"], 1)
        self.assertEqual(score["status_correct"], 14)
        self.assertFalse(score["all_passed"])

    def test_missing_results_are_not_auto_pass_or_auto_review(self):
        predictions = self.make_perfect_predictions()
        predictions["cases"] = [predictions["cases"][0]]
        score = evaluate(self.catalog, predictions)
        self.assertEqual(score["received"], 1)
        self.assertEqual(score["status_correct"], 1)
        self.assertGreaterEqual(score["missed_fail"], 6)
        self.assertFalse(score["all_passed"])
        missing = [x for x in score["cases"] if x["actual"] is None]
        self.assertEqual(len(missing), 15)

    def test_trace_and_line_evidence_fail_without_faking_status(self):
        predictions = self.make_perfect_predictions()
        row = predictions["cases"][0]
        row["inspected_paths"] = []
        row["evidence"][0]["line_start"] = 99999
        row["evidence"][0]["line_end"] = 99999
        result = evaluate(self.catalog, predictions)
        entry = next(x for x in result["cases"] if x["case_id"] == row["case_id"])
        self.assertTrue(entry["status_match"])
        self.assertFalse(entry["trace_complete"])
        self.assertFalse(entry["evidence_valid"])
        self.assertFalse(entry["passed"])
        self.assertEqual(result["status_correct"], 16)

    def test_review_requires_specific_external_artifact_not_generic_tests(self):
        predictions = self.make_perfect_predictions()
        entry = next(x for x in predictions["cases"] if x["case_id"] == "recovery-drill-external")
        entry["decision_reason"] = "已查核備份程式；待確認：需補動態測試結果及邊界案例紀錄"
        result = evaluate(self.catalog, predictions)
        detail = next(x for x in result["cases"] if x["case_id"] == entry["case_id"])
        self.assertTrue(detail["status_match"])
        self.assertFalse(detail["review_gap_specific"])
        self.assertFalse(detail["passed"])
        self.assertEqual(result["review_gap_specific_count"], 1)

    def test_unknown_duplicate_or_invalid_predictions_are_rejected(self):
        for mutation in ("unknown", "duplicate", "invalid_status", "invalid_finding"):
            with self.subTest(mutation=mutation):
                predictions = self.make_perfect_predictions()
                if mutation == "unknown":
                    predictions["cases"][0]["case_id"] = "not-a-real-case"
                elif mutation == "duplicate":
                    predictions["cases"].append(dict(predictions["cases"][0]))
                elif mutation == "invalid_status":
                    predictions["cases"][0]["status"] = "completed"
                elif mutation == "invalid_finding":
                    predictions["cases"][0]["finding"] = "yes"
                with self.assertRaises(ValueError):
                    evaluate(self.catalog, predictions)

    def test_assessment_mode_only_imports_existing_real_case_artifacts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            materialize(root, self.catalog)
            case = self.catalog["cases"][0]
            assessment_dir = root / case["id"] / "reports/security-code-review"
            assessment_dir.mkdir(parents=True)
            (assessment_dir / "assessment.json").write_text(json.dumps({
                "checks": [{"id": case["rule_id"], "status": case["expected_status"],
                            "finding_ids": [],
                            "execution": {"state": "completed", "inspected_paths": case["required_paths"]},
                            "evidence": [{"kind": "source", "path": case["anchor"]["path"],
                                          "line_start": 1, "line_end": 1}]}],
                "findings": [],
            }), encoding="utf-8")
            actual = assessment_predictions(root, self.catalog)
            self.assertEqual(len(actual["cases"]), 1)
            self.assertEqual(actual["cases"][0]["case_id"], case["id"])
            self.assertFalse(evaluate(self.catalog, actual)["all_passed"])
            # 來源已有記錄也不代表真正完成；不能把 pending 當成有效判定。
            raw = json.loads((assessment_dir / "assessment.json").read_text("utf-8"))
            raw["checks"][0]["execution"]["state"] = "pending"
            (assessment_dir / "assessment.json").write_text(json.dumps(raw), encoding="utf-8")
            self.assertEqual(assessment_predictions(root, self.catalog)["cases"], [])

    def test_nonexistent_finding_id_does_not_count_as_real_finding(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            materialize(root, self.catalog)
            case = next(x for x in self.catalog["cases"] if x["expected_status"] == "fail")
            target = root / case["id"] / "reports/security-code-review"
            target.mkdir(parents=True)
            target.joinpath("assessment.json").write_text(json.dumps({
                "checks": [{"id": case["rule_id"], "status": "fail",
                            "finding_ids": ["does-not-exist"],
                            "execution": {"state": "completed",
                                          "inspected_paths": case["required_paths"]},
                            "evidence": [{"kind": "source", "path": case["anchor"]["path"],
                                          "line_start": 1, "line_end": 1}]}],
                "findings": []
            }), encoding="utf-8")
            predictions = assessment_predictions(root, self.catalog)
            self.assertFalse(predictions["cases"][0]["finding"])
            result = evaluate(self.catalog, predictions)
            detail = next(x for x in result["cases"] if x["case_id"] == case["id"])
            self.assertTrue(detail["status_match"])
            self.assertFalse(detail["finding_match"])
            self.assertFalse(detail["passed"])

    def test_cli_writes_machine_readable_evaluation_and_returns_nonzero_on_regression(self):
        with tempfile.TemporaryDirectory() as temp:
            predictions = self.make_perfect_predictions()
            data = Path(temp) / "predictions.json"
            report = Path(temp) / "score.json"
            data.write_text(json.dumps(predictions), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--evaluate", str(data), "--output", str(report)]), 0)
            self.assertTrue(json.loads(report.read_text("utf-8"))["all_passed"])
            predictions["cases"][0]["status"] = "fail"
            predictions["cases"][0]["finding"] = True
            data.write_text(json.dumps(predictions), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--evaluate", str(data)]), 1)


if __name__ == "__main__":
    unittest.main()
