"""摘要自動推論回歸測試：嚴禁依缺乏程式碼線索判定低風險或無個資。"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from report_enrichment import (
    infer_personal_data, resolve_personal_data, detect_reviewer,
    build_overall_risk, build_pending_information,
)


class ReportEnrichmentTests(unittest.TestCase):
    def test_personal_data_follows_completed_paths_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "person.cs").write_text("public string NationalId { get; set; }\n", encoding="utf-8")
            assessment = {"checks": [
                {"id": "PD-01", "execution": {"state": "pending", "inspected_paths": ["person.cs"]}}
            ]}
            unknown = infer_personal_data(assessment, root)
            self.assertEqual(unknown["status"], "待確認")
            self.assertFalse(unknown["evidence"])
            assessment["checks"][0]["execution"]["state"] = "completed"
            found = infer_personal_data(assessment, root)
            self.assertEqual(found["status"], "是")
            self.assertEqual(found["evidence"][0]["path"], "person.cs")
            self.assertEqual(found["evidence"][0]["line_start"], 1)

    def test_personal_data_does_not_infer_negative_from_no_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.cs").write_text("public int Total => 1;\n", encoding="utf-8")
            assessment = {"checks": [
                {"id": "PD-01", "execution": {"state": "completed", "inspected_paths": ["app.cs"]}}
            ]}
            project = {}
            resolve_personal_data(project, assessment, root, ("cp950", "cp1252"))
            self.assertEqual(project["personal_data"], "待確認")
            self.assertIn("無法證明", project["personal_data_assessment"]["basis"])
            supplied = {"personal_data": "否"}
            resolve_personal_data(supplied, assessment, root, ("cp950", "cp1252"))
            self.assertEqual(supplied["personal_data"], "否")
            self.assertFalse(supplied["personal_data_assessment"]["evidence"])

    def test_reviewer_never_guesses_app_vs_cli(self):
        self.assertEqual(detect_reviewer(None, {}), "AI 審查工具（執行介面無法辨識）")
        self.assertEqual(detect_reviewer(None, {"CODEX_THREAD_ID": "123"}),
                         "Codex（執行介面無法辨識）")
        self.assertEqual(detect_reviewer(None, {"CLAUDECODE": "1"}), "Claude Code")
        self.assertEqual(detect_reviewer(None, {"SECURITY_CODE_REVIEW_EXECUTOR": "Codex CLI"}),
                         "Codex CLI")
        self.assertEqual(detect_reviewer("Codex App", {"CODEX_THREAD_ID": "1"}), "Codex App")
        self.assertEqual(detect_reviewer(None, {"SECURITY_CODE_REVIEW_EXECUTOR": "Unsupported"}),
                         "AI 審查工具（執行介面無法辨識）")

    def test_risk_uses_maximum_confirmed_severity_not_count(self):
        risk = build_overall_risk({"findings": [
            {"id": "F-01", "severity": "low", "impact": "有限影響"},
            {"id": "F-02", "severity": "critical", "impact": "可能存取核心資料", "confidence": "high"},
            {"id": "F-03", "severity": "low", "impact": "輕微"}
        ], "checks": [{"status": "review"}]})
        self.assertEqual(risk["level"], "critical")
        self.assertIn("F-02", risk["summary"])
        self.assertIn("可利用性", risk["summary"])
        self.assertIn("1 項規則", risk["summary"])

    def test_no_findings_does_not_mean_low_risk(self):
        risk = build_overall_risk({"findings": [], "checks": []})
        self.assertEqual(risk["level"], "review")
        self.assertIn("未發現不代表低風險", risk["summary"])

    def test_pending_information_from_project_and_checks(self):
        project = {
            "personal_data": "待確認",
            "security_level_assessment": {"missing_information": ["機關正式等級"]}
        }
        assessment = {"checks": [
            {"id": "AC-01", "status": "review"},
            {"id": "AU-01", "status": "pass"},
        ]}
        pending = build_pending_information(project, assessment, ["尚缺實機回應", "尚缺實機回應"])
        self.assertIn("機關正式等級", pending)
        self.assertTrue(any("個資" in s for s in pending))
        self.assertTrue(any("AC-01" in s for s in pending))
        self.assertEqual(pending.count("尚缺實機回應"), 1)


if __name__ == "__main__":
    unittest.main()
