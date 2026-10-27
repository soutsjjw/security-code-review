"""Q5 70 項判定契約與真實報告驗收守門的正反測試。

合成工件只測試驗證器；不得作為 Agent 真實掃描成果。
"""
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

from control_effectiveness import REQUIRED_SCENARIOS
from quality_gate import (QUALITY_VERSIONS, REPORT_DIR, compare_project,
                          contract_matrix, main, measure)
from review_completion import completion_errors
from review_decision import decision_quality_errors
from review_queue import load_rules


class RuleContractTests(unittest.TestCase):
    def test_all_seventy_have_explicit_rule_specific_bypass_scenarios(self):
        result = contract_matrix()
        self.assertTrue(result["passed"], result["errors"])
        self.assertEqual(result["rule_count"], 70)
        self.assertEqual(result["valid_count"], 70)
        self.assertEqual(len(REQUIRED_SCENARIOS), 70)
        self.assertEqual(
            {item["rule_id"] for item in result["rows"]}, set(REQUIRED_SCENARIOS))
        for row in result["rows"]:
            with self.subTest(rule=row["rule_id"]):
                self.assertGreaterEqual(len(row["scenario_types"]), 2)
                self.assertEqual(len(row["applicability_cases"]), 3)
                self.assertEqual(len(row["decision_paths"]), 4)
                self.assertTrue(row["contract_valid"])

    def test_contract_fails_if_one_rule_is_missing_specific_attack_case(self):
        with patch.dict("quality_gate.REQUIRED_SCENARIOS", {"LG-05": (
                "alternate_or_bypass_path",)}, clear=False):
            failures = contract_matrix()
        self.assertFalse(failures["passed"])
        self.assertTrue(any("LG-05" in item for item in failures["errors"]))

    def test_all_70_rule_modes_block_template_decisions_and_fake_completed(self):
        _, rules = load_rules()
        for rule in rules:
            rid = rule["id"]
            with self.subTest(rule=rid):
                row = {
                    "id": rid, "status": "pass",
                    "decision_reason": "結論依靜態證據與外部證據缺口判定",
                    "evidence": [], "execution": {
                        "state": "completed", "methods": [],
                        "summary": "", "inspected_paths": []},
                }
                self.assertTrue(any("制式結論" in e for e in
                                    decision_quality_errors([row])))
                self.assertTrue(completion_errors([row]))
                row["status"] = "review"
                self.assertTrue(completion_errors([row]))
                row["status"] = "fail"
                self.assertTrue(completion_errors([row]))
                row["status"] = "na"
                self.assertTrue(completion_errors([row]))

    def test_matrix_only_cli_produces_contract_audit_not_security_score(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(main(["--matrix-only"]), 0)
        result = json.loads(out.getvalue())
        self.assertEqual(result["measurement_source"], "static_quality_contracts")
        self.assertNotIn("status_accuracy", result)
        self.assertNotIn("quality_gate_passed", result)


class RealProjectQualityGateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "Case"
        self.root.mkdir()
        self.report = self.root / REPORT_DIR
        self.report.joinpath("analysis").mkdir(parents=True)
        self.source = self.root / "Program.cs"
        self.source.write_text("public class Program { public bool Ready() => true; }\n",
                               encoding="utf-8")
        _, rules = load_rules()
        self.ids = sorted(r["id"] for r in rules)
        checks = [
            {"id": rid, "status": "na", "finding_ids": [],
             "execution": {"state": "completed", "inspected_paths": ["Program.cs"]},
             "evidence": [], "decision_reason": "本案例以模擬輸入測試驗證器"}
            for rid in self.ids
        ]
        self.data = {
            "project_id": "Case", "assessment_date": "2026-10-24",
            "checks": checks, "findings": [],
        }
        self.index = {key: 1 for key in QUALITY_VERSIONS}
        self.snapshot = {"git_revision": "source-test-version",
                         "source_hashes": {"Program.cs": "static-source-hash"}}
        self.queue = {
            "completed": 70, "ready_for_report": True,
            "source_coverage": {"source_file_count": 1,
                                "reviewed_source_file_count": 1,
                                "missing_source_file_count": 0},
            "second_pass": {"enabled": True, "baseline_ready": True,
                            "completed": 70, "pending_count": 0},
        }
        self.save()

    def save(self):
        (self.report / "assessment.json").write_text(
            json.dumps(self.data, ensure_ascii=False), encoding="utf-8")
        (self.report / "analysis/structure-index.json").write_text(
            json.dumps(self.index), encoding="utf-8")
        (self.report / "analysis/review-snapshot.json").write_text(
            json.dumps(self.snapshot), encoding="utf-8")

    def fake_measure(self, previous=None, queue=None, report_errors=None):
        self.save()
        with patch("quality_gate.build_queue", return_value=self.queue if queue is None else queue), \
             patch("quality_gate.report_artifact_errors",
                   return_value=[] if report_errors is None else report_errors):
            return measure(self.root, previous=previous)

    def test_missing_real_artifacts_are_never_fabricated(self):
        (self.report / "assessment.json").unlink()
        with self.assertRaisesRegex(ValueError, "缺少正式 assessment"):
            measure(self.root)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--target", str(self.root)]), 2)

    def test_fixture_audit_stays_separate_from_agent_accuracy(self):
        result = self.fake_measure()
        self.assertTrue(result["quality_gate_passed"])
        self.assertEqual(result["measurement_source"], "real_project_artifacts")
        self.assertEqual(result["contracts"]["valid_count"], 70)
        self.assertEqual(result["verified_second_pass_count"], 70)
        self.assertIn("不能單獨證明", result["trust_limit"])
        self.assertNotIn("status_accuracy", result)

    def test_q1_to_q4_missing_version_blocks_acceptance(self):
        for field in QUALITY_VERSIONS:
            with self.subTest(field=field):
                self.index.pop(field)
                result = self.fake_measure()
                self.assertFalse(result["quality_gate_passed"])
                self.assertTrue(any(field in x for x in result["diagnostics"]))
                self.index[field] = 1

    def test_pending_second_pass_invalid_report_or_low_coverage_blocks(self):
        q = copy.deepcopy(self.queue)
        q["second_pass"]["pending_count"] = 3
        self.assertFalse(self.fake_measure(queue=q)["quality_gate_passed"])
        self.assertFalse(self.fake_measure(report_errors=["HTML 與 JSON 不一致"])["quality_gate_passed"])
        q = copy.deepcopy(self.queue)
        q["source_coverage"]["reviewed_source_file_count"] = 0
        self.assertFalse(self.fake_measure(queue=q)["quality_gate_passed"])
        q = copy.deepcopy(self.queue)
        q["ready_for_report"] = False
        q["rule_integrity_errors"] = ["AC-01: 來源未驗證"]
        blocked = self.fake_measure(queue=q)
        self.assertIn("AC-01: 來源未驗證", blocked["diagnostics"])

    def test_existing_fail_finding_regression_is_not_silenced(self):
        failed = next(c for c in self.data["checks"] if c["id"] == "AC-01")
        failed.update(status="fail", finding_ids=["F-001"], evidence=[
            {"kind": "source", "path": "Program.cs", "line_start": 1, "line_end": 1},
        ])
        self.data["findings"] = [{"id": "F-001", "check_ids": ["AC-01"]}]
        previous = self.fake_measure()
        self.assertTrue(previous["quality_gate_passed"])
        failed["status"] = "review"
        failed["finding_ids"] = []
        latest = self.fake_measure(previous=previous)
        self.assertFalse(latest["quality_gate_passed"])
        self.assertTrue(any("既有 Fail" in x for x in latest["regressions"]))
        self.assertTrue(any("Finding" in x for x in latest["regressions"]))

    def test_source_revision_or_different_project_cannot_be_compared(self):
        previous = self.fake_measure()
        self.snapshot["source_hashes"]["Program.cs"] = "different-source-sha"
        with self.assertRaisesRegex(ValueError, "來源版本"):
            self.fake_measure(previous=previous)
        self.snapshot["source_hashes"]["Program.cs"] = "static-source-hash"
        previous["project_id"] = "OtherProject"
        with self.assertRaisesRegex(ValueError, "專案不同"):
            self.fake_measure(previous=previous)

    def test_snapshot_and_report_errors_never_become_fake_success(self):
        q = copy.deepcopy(self.queue)
        q["safety_integrity_errors"] = ["來源 Git 指紋失效"]
        latest = self.fake_measure(queue=q)
        self.assertFalse(latest["quality_gate_passed"])
        self.assertIn("來源 Git 指紋失效", latest["diagnostics"])

    def test_all_70_still_required_in_real_project_artifact(self):
        self.data["checks"].pop()
        with self.assertRaisesRegex(ValueError, "完整且唯一"):
            self.fake_measure()

    def test_existing_review_count_is_descriptive_not_an_arbitrary_threshold(self):
        for check in self.data["checks"]:
            check["status"] = "review"
        result = self.fake_measure()
        self.assertTrue(result["quality_gate_passed"])
        self.assertEqual(result["status_counts"]["review"], 70)
        # 本測試用模擬的 build_queue；正式執行須通過真實 Q1~Q4 的判定守門。


    def test_project_acceptance_requires_full_verified_queue_not_compact_preview(self):
        self.save()
        seen = []

        def checked_queue(data, rules, batch_size, *, source_root=None, compact=False, **kwargs):
            seen.append((compact, source_root))
            if compact:
                return {"completed": 70, "ready_for_report": False,
                        "source_coverage": {"source_file_count": 1,
                                            "reviewed_source_file_count": 1,
                                            "missing_source_file_count": 0,
                                            "verified": False}}
            return copy.deepcopy(self.queue)

        with patch("quality_gate.build_queue", side_effect=checked_queue), \
             patch("quality_gate.report_artifact_errors", return_value=[]):
            outcome = measure(self.root)
        self.assertTrue(outcome["quality_gate_passed"], outcome["diagnostics"])
        self.assertEqual(seen, [(False, self.root.resolve())])



if __name__ == "__main__":
    unittest.main()
