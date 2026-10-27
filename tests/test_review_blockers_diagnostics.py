"""First-pass diagnostics must be actionable and must never alter evidence."""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from review_blockers import classify, diagnose, summarize


class BlockerDiagnosticsTests(unittest.TestCase):
    def test_orphan_examples_do_not_invent_ac01_owner(self):
        message = ("存在 1918 筆未經逐檔驗證的 inspected_paths（前 10 筆）："
                   "AC-01 → src/Infrastructure/Identity/IdentityService.cs")
        diag = {"total": 1918, "fingerprint": "actual-pair-set",
                "by_rule": {"AU-09": 20, "IN-05": 1898},
                "by_reason": {"missing_rule_review": 1918},
                "examples": [{"rule_id": "AU-09", "path": "Example.cs",
                              "reason": "missing_rule_review"}]}
        first = summarize([message], link_diagnostics=diag)
        self.assertEqual(first["blocked_count"], 1)
        self.assertEqual(first["recheck_rule_ids"], ["AU-09", "IN-05"])
        self.assertEqual(first["blockers"][0]["category"], "file_review_links")
        self.assertEqual(first["inspected_paths_diagnostic"]["total"], 1918)
        self.assertEqual(first["blockers"][0]["rule_ids"], ["AU-09", "IN-05"])
        self.assertEqual(first["inspected_paths_diagnostic"], diag)
        self.assertEqual(diag["total"], 1918)

    def test_same_error_preview_but_different_links_changes_signature(self):
        msgs = ["存在 1918 筆未經逐檔驗證的 inspected_paths（前 10 筆）：AC-01 → A.cs"]
        first = summarize(msgs, link_diagnostics={
            "total": 1918, "fingerprint": "revision-a",
            "by_rule": {"IN-01": 1918}})
        second = summarize(msgs, link_diagnostics={
            "total": 1918, "fingerprint": "revision-b",
            "by_rule": {"IN-01": 1918}})
        self.assertNotEqual(first["blocker_signature"], second["blocker_signature"])

    def test_precise_actionable_categories(self):
        errors = [
            "AU-09: 尚有 55 筆跨檔／組態候選未查證或排除：relation-1",
            "DP-04: Q2 控制鏈與正式檢核來源證據無交集",
            "DP-04: Q3 external_boundary 情境未與實際失效／控制執行點連結",
            "SI-01: 完成證據僅包含 using／註解／宣告／空結構等無效來源片段",
            "AC-08: Foo.cs:1-10 引用程式碼與本規則的控制行為無關",
        ]
        actual = summarize(errors)
        kinds = {item["category"] for item in actual["blockers"]}
        self.assertEqual(kinds, {"cross_file_candidates", "control_trace",
                                 "control_outcome", "weak_source_evidence",
                                 "unrelated_evidence"})
        self.assertEqual(actual["recheck_rule_ids"],
                         ["AC-08", "AU-09", "DP-04", "SI-01"])
        self.assertEqual(classify("SI-01: 完成證據僅包含無效來源片段"),
                         "weak_source_evidence")

    def test_diagnosis_preserves_assessment_and_displays_exact_relation_ids(self):
        data = {"checks": [], "findings": [{"id": "F-001"}]}
        untouched = copy.deepcopy(data)

        def fake_first_pass(target, assessment, *, diagnostics=None):
            diagnostics["cross_file_candidates"] = {
                "AU-09": {"count": 2, "relationship_ids": ["edge-a", "edge-b"]}}
            diagnostics["unverified_inspected_paths"] = {
                "total": 0, "fingerprint": "empty", "by_rule": {}}
            return ["AU-09: 尚有 2 筆跨檔／組態候選未查證或排除：edge-a"]

        with patch("adversarial_recheck.first_pass_issues", side_effect=fake_first_pass):
            result = diagnose(Path("."), data)
        self.assertEqual(result["cross_file_candidates"]["AU-09"]["relationship_ids"],
                         ["edge-a", "edge-b"])
        self.assertNotIn("inspected_paths_diagnostic", result)
        self.assertEqual(data, untouched)


if __name__ == "__main__":
    unittest.main()
