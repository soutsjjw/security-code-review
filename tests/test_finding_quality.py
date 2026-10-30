"""Finding 品質啟發式：死碼、設計說明註解、impact_type。"""
import sys
import tempfile
import unittest
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_ROOT / 'scripts/lib'))
from assessment_consistency import finding_quality_issues, impact_type_label
from report_enrichment import build_overall_risk

HANDLER = """public class Handler
{
    public async Task<Result> Handle()
    {
        var secret = Generate();
        var qrCodeUrl = $"https://chart.example/?chl={secret}";
        var uri = Build(secret);
        using var png = QrCode(uri);
        return new Result { Secret = secret, Image = png };
    }
}
"""

VIEW = """@* 不加入 SRI 的原因：供應商不支援固定雜湊 *@
<script src="https://cdn.example/api.js" async defer></script>
"""


def finding(path, start, end, text="說明", **extra):
    ev = {"kind": "source", "path": path, "line_start": start, "line_end": end,
          "description": text, "collected_on": "2026-10-23", "source_version": "x"}
    return {"id": "F-1", "title": "測試 Finding", "severity": "high", "impact": "影響", "confidence": "confirmed",
            "check_ids": ["AU-09"], "evidence": [ev], **extra}


class QualityTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        (self.root / "Handler.cs").write_text(HANDLER, encoding="utf-8")
        (self.root / "View.cshtml").write_text(VIEW, encoding="utf-8")

    def run_check(self, *findings):
        return finding_quality_issues({"findings": list(findings)}, self.root)

    def test_unused_variable_named_in_finding_is_error(self):
        errors, _ = self.run_check(finding("Handler.cs", 5, 8, "qrCodeUrl 把 secret 送往第三方"))
        self.assertEqual(len(errors), 1)
        self.assertIn("qrCodeUrl", errors[0])
        self.assertIn("死碼", errors[0])

    def test_unused_variable_cited_by_single_line_number_is_error(self):
        errors, _ = self.run_check(finding("Handler.cs", 5, 8, "第6行建立第三方 URL"))
        self.assertTrue(any("qrCodeUrl" in e for e in errors))

    def test_wide_range_citation_does_not_blame_unused_variable(self):
        errors, _ = self.run_check(finding("Handler.cs", 3, 9, "第3-9行處理 secret"))
        self.assertEqual(errors, [])

    def test_used_variable_is_not_flagged(self):
        errors, _ = self.run_check(finding("Handler.cs", 5, 8, "secret 被回傳給呼叫端，第5行產生"))
        self.assertEqual(errors, [])

    def test_usage_traced_suppresses_dead_code_error(self):
        errors, _ = self.run_check(finding(
            "Handler.cs", 5, 8, "qrCodeUrl 把 secret 送往第三方",
            verification={"usage_traced": "已追查全專案，qrCodeUrl 由反射讀取並回傳前端"}))
        self.assertEqual(errors, [])

    def test_design_note_comment_warns_and_can_be_acknowledged(self):
        _, warnings = self.run_check(finding("View.cshtml", 2, 2, "script 未使用 SRI"))
        self.assertTrue(any("設計說明註解" in w for w in warnings))
        _, warnings = self.run_check(finding(
            "View.cshtml", 2, 2, "script 未使用 SRI",
            verification={"design_notes": "註解說明供應商不支援 SRI，已評估仍列低風險"}))
        self.assertFalse(any("設計說明註解" in w for w in warnings))

    def test_high_availability_only_warns(self):
        _, warnings = self.run_check(finding("Handler.cs", 5, 8, "secret", impact_type=["availability"]))
        self.assertTrue(any("只有可用性" in w for w in warnings))
        _, warnings = self.run_check(
            finding("Handler.cs", 5, 8, "secret", impact_type=["availability", "integrity"]))
        self.assertFalse(any("只有可用性" in w for w in warnings))

    def test_missing_impact_type_is_summarized(self):
        _, warnings = self.run_check(finding("Handler.cs", 5, 8, "secret"))
        self.assertTrue(any("未標示 impact_type" in w for w in warnings))

    def test_unreadable_source_is_ignored(self):
        errors, _ = self.run_check(finding("Missing.cs", 1, 2))
        self.assertEqual(errors, [])


class ImpactTypeReportTests(unittest.TestCase):
    def test_label_and_risk_summary(self):
        f = {"id": "F-1", "severity": "high", "impact": "令牌外洩", "confidence": "confirmed",
             "impact_type": ["confidentiality", "integrity"]}
        self.assertEqual(impact_type_label(f), "機密性、完整性")
        self.assertIn("影響面向：機密性、完整性", build_overall_risk({"findings": [f], "checks": []})["summary"])

    def test_no_label_when_absent(self):
        self.assertEqual(impact_type_label({"id": "F-1"}), "")


if __name__ == "__main__":
    unittest.main()
