"""P0–P3 /goal continuation: real queue preparation, diagnostics and audited revisions."""
from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import evidence_integrity as ledger
from analysis_prepare import prepare
from first_pass_repair import repair_plan
from review_blockers import diagnose
from review_log import logged_main
from review_queue import initialize, load_rules
from review_safety import _write, integrate, stage


class GoalEndToEndSmokeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.report = self.root / "reports/security-code-review"
        (self.root / "Example.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
            '<TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>',
            encoding="utf-8")
        (self.root / "Handler.cs").write_text(
            "public bool CanAccess(int id) => id > 0;\n", encoding="utf-8")
        with patch("analysis_prepare.probe_roslyn", return_value={"available": False}), \
             patch("analysis_prepare.probe_codegraph", return_value={"available": False}):
            prepare(self.root)
        ruleset, rules = load_rules()
        initialize(self.root, self.report, ruleset, rules)
        self.assertEqual(ledger.errors(self.root), [])

    def test_initialized_pending_queue_diagnoses_and_plans_missing_sources(self):
        assessment = json.loads((self.report / "assessment.json").read_text("utf-8"))
        before = copy.deepcopy(assessment)
        diagnosis = diagnose(self.root, assessment)
        self.assertEqual(diagnosis["pending_rule_count"], 70)
        self.assertFalse(diagnosis["ready_for_second_pass"])
        self.assertIn("Handler.cs", diagnosis["missing_source_paths"])
        self.assertIn("Example.csproj", diagnosis["missing_source_paths"])
        plan = repair_plan(assessment, diagnosis)
        self.assertGreaterEqual(plan["candidate_repair_file_count"], 2)
        paths = {row["path"]: row for row in plan["priority_files"]}
        self.assertTrue(paths["Handler.cs"]["missing_file_review"])
        self.assertEqual(assessment, before)
        self.assertEqual(ledger.errors(self.root), [])
        self.assertFalse((self.report / "analysis/first-pass-baseline.json").exists())

    def test_finding_revision_requires_explicit_gate_and_preserves_old_evidence(self):
        previous = {
            "id": "F-001", "title": "已確認的資源越權缺陷", "severity": "high",
            "confidence": "confirmed", "check_ids": ["AC-08"],
            "evidence": [{"kind": "source", "path": "Handler.cs",
                          "line_start": 1, "line_end": 1}],
            "impact": "可能越權存取", "remediation": "修正授權驗證",
        }
        # Every setup mutation uses the authenticated transaction instead of
        # rewriting the assessment outside of Manifest / Journal.
        existing = json.loads((self.report / "assessment.json").read_text("utf-8"))
        existing["findings"] = [previous]
        ledger.commit(self.root, {"assessment.json": existing}, event="test-seeded-finding")
        revised = copy.deepcopy(previous)
        revised["title"] = "已確認的資源存取缺陷（修正敘述）"
        staged_input = self.report / "finding-correction.json"
        _write(staged_input, {
            "findings": [revised],
            "finding_revisions": {"F-001": {
                "reason": "重新閱讀實際資源存取端點及驗證路徑，原標題範圍過大；保留已確認的漏洞、原始證據與等級。",
                "reviewer": "security-review-agent",
            }},
        })
        stage(self.root, staged_input)
        with self.assertRaisesRegex(ValueError, "須明確授權"):
            integrate(self.root)
        self.assertEqual(ledger.errors(self.root), [])
        output = integrate(self.root, allow_revision=True, allow_finding_revision=True)
        self.assertEqual(output["findings"], 1)
        current = json.loads((self.report / "assessment.json").read_text("utf-8"))
        self.assertEqual(current["findings"], [revised])
        audit = current["finding_amendments"]
        self.assertEqual(len(audit), 1)
        self.assertEqual(audit[0]["previous_finding"], previous)
        self.assertEqual(len(audit[0]["previous_sha256"]), 64)
        self.assertNotEqual(audit[0]["previous_sha256"], audit[0]["updated_sha256"])
        self.assertEqual(ledger.errors(self.root), [])
        self.assertFalse(list((self.report / "analysis/staged").glob("*.json")))

    def test_confirmed_finding_cannot_be_downgraded_by_revision(self):
        original = {"id": "F-2", "title": "缺陷", "severity": "high",
                    "confidence": "confirmed", "check_ids": ["AC-08"],
                    "evidence": [{"path": "Handler.cs"}]}
        original_assessment = json.loads((self.report / "assessment.json").read_text("utf-8"))
        original_assessment["findings"] = [original]
        ledger.commit(self.root, {"assessment.json": original_assessment}, event="test-seeded")
        lowered = dict(original, severity="low")
        draft = self.report / "lowered.json"
        _write(draft, {"findings": [lowered], "finding_revisions": {"F-2": {
            "reason": "再次核對身分驗證與資料存取流程，確認原始越權缺陷仍可重現；本次測試刻意嘗試降低嚴重度，應由工具拒絕並保留原始 Finding 證據。",
            "reviewer": "security-review-agent",
        }}})
        stage(self.root, draft)
        with self.assertRaisesRegex(ValueError, "嚴重度"):
            integrate(self.root, allow_revision=True, allow_finding_revision=True)
        self.assertEqual(ledger.errors(self.root), [])

    def test_stalled_run_allows_only_readonly_diagnosis(self):
        def no_write():
            return 0
        for options, expected in [
            (["--diagnose-first-pass"], 0),
            (["--repair-plan"], 0),
            (["--detail-id", "AC-08"], 0),
            (["--integrate"], 3),
        ]:
            with self.subTest(options=options), \
                 patch("sys.argv", ["review_queue.py", "--target", str(self.root), *options]), \
                 patch("review_log._load", return_value={"status": "stalled"}):
                self.assertEqual(logged_main(no_write, "queue"), expected)


if __name__ == "__main__":
    unittest.main()
