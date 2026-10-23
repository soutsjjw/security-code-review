"""assessment 一致性檢查：Finding／status 連動、理由矛盾、佔位字、截斷、review 比例。"""
import sys
import tempfile
import unittest
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_ROOT / 'scripts'))
from assessment_consistency import (
    clip_text, consistency_errors, consistency_warnings, detect_language_framework,
    project_placeholder_errors,
)
from report_enrichment import build_overall_risk, build_pending_information


def check(cid, status, reason="已核對來源並確認結論", **extra):
    return {"id": cid, "status": status, "decision_reason": reason, **extra}


def finding(fid, ids, confidence="confirmed", severity="high"):
    return {"id": fid, "check_ids": ids, "confidence": confidence, "severity": severity}


class FindingStatusLinkTests(unittest.TestCase):
    def test_confirmed_finding_with_review_check_is_rejected(self):
        data = {"checks": [check("IN-02", "review")], "findings": [finding("F-1", ["IN-02"])]}
        errors = consistency_errors(data)
        self.assertEqual(len(errors), 1)
        self.assertIn("F-1", errors[0])
        self.assertIn("IN-02=review", errors[0])

    def test_confirmed_finding_with_pass_check_is_rejected(self):
        data = {"checks": [check("IN-02", "pass"), check("CR-05", "fail")],
                "findings": [finding("F-1", ["IN-02", "CR-05"])]}
        self.assertTrue(any("IN-02" in e and "pass" in e for e in consistency_errors(data)))

    def test_one_fail_among_linked_checks_is_enough(self):
        data = {"checks": [check("CR-05", "fail"), check("IN-02", "review")],
                "findings": [finding("F-1", ["CR-05", "IN-02"])]}
        self.assertEqual(consistency_errors(data), [])

    def test_unconfirmed_finding_may_stay_review(self):
        data = {"checks": [check("IN-02", "review")],
                "findings": [finding("F-1", ["IN-02"], confidence="medium")]}
        self.assertEqual(consistency_errors(data), [])


class ReasonContradictionTests(unittest.TestCase):
    def test_fail_reason_that_keeps_review_is_rejected(self):
        data = {"checks": [check("AC-01", "fail", "尚缺完整組態證據，故保留 review")], "findings": []}
        self.assertTrue(any("AC-01" in e for e in consistency_errors(data)))

    def test_review_reason_may_mention_review(self):
        data = {"checks": [check("AC-01", "review", "尚缺部署證據，故保留 review")], "findings": []}
        self.assertEqual(consistency_errors(data), [])

    def test_clean_fail_reason_passes(self):
        data = {"checks": [check("AC-01", "fail", "伺服器端未設定逾時，已建立 Finding")], "findings": []}
        self.assertEqual(consistency_errors(data), [])


class PlaceholderTests(unittest.TestCase):
    def test_placeholder_framework_rejected(self):
        self.assertTrue(project_placeholder_errors({"name": "x", "language_framework": "待實際盤點"}))
        self.assertTrue(project_placeholder_errors({"name": "x", "language_framework": "未能自動辨識（Agent 須依實際盤點填寫）"}))
        self.assertTrue(project_placeholder_errors({"name": "x"}))
        self.assertFalse(project_placeholder_errors({"name": "x", "language_framework": "ASP.NET Core 8"}))

    def test_framework_detected_from_csproj(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src/Web").mkdir(parents=True)
            (root / "src/Web/Web.csproj").write_text(
                '<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup>'
                '<TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>', encoding="utf-8")
            (root / "bin").mkdir()
            (root / "bin/Ignored.csproj").write_text(
                '<Project><TargetFramework>net4.8</TargetFramework></Project>', encoding="utf-8")
            result = detect_language_framework(root)
            self.assertIn("ASP.NET Core", result)
            self.assertIn("net8.0", result)
            self.assertNotIn("net4.8", result)

    def test_undetectable_framework_stays_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(project_placeholder_errors(
                {"language_framework": detect_language_framework(Path(tmp))}))


class TruncationTests(unittest.TestCase):
    def test_clip_cuts_at_clause_boundary_and_marks_it(self):
        text = "第一段影響說明，第二段影響說明，第三段影響說明很長很長很長很長"
        clipped = clip_text(text, 20)
        self.assertTrue(clipped.endswith("…"))
        self.assertLessEqual(len(clipped), 21)
        self.assertNotIn("第三段", clipped)

    def test_short_text_unchanged(self):
        self.assertEqual(clip_text("短句。", 100), "短句。")

    def test_overall_risk_no_longer_cuts_mid_word(self):
        impact = "管理者開啟 modal 時可能執行 JavaScript。" * 8 + "Roles Index 的 fetch 回應直接串入 innerHTML"
        risk = build_overall_risk({"findings": [
            {"id": "F-1", "severity": "high", "impact": impact, "confidence": "confirmed"}], "checks": []})
        self.assertNotIn("fetc；", risk["summary"])
        self.assertIn("…", risk["summary"])

    def test_overall_risk_reports_finding_distribution(self):
        risk = build_overall_risk({"findings": [
            {"id": "F-1", "severity": "high", "impact": "甲", "confidence": "confirmed"},
            {"id": "F-2", "severity": "high", "impact": "乙", "confidence": "confirmed"},
            {"id": "F-3", "severity": "med", "impact": "丙", "confidence": "confirmed"}], "checks": []})
        self.assertIn("共 3 筆", risk["summary"])
        self.assertIn("高 2 筆", risk["summary"])


class ReviewRatioTests(unittest.TestCase):
    def _assessment(self, review, other, **extra):
        return {"checks": [check(f"AC-{i:02d}", "review", **extra) for i in range(review)]
                + [check(f"AU-{i:02d}", "pass") for i in range(other)]}

    def test_high_ratio_warns_but_does_not_block(self):
        data = self._assessment(8, 2)
        self.assertTrue(consistency_warnings(data))
        self.assertEqual(consistency_errors(data), [])

    def test_low_ratio_no_warning(self):
        self.assertEqual(consistency_warnings(self._assessment(5, 5)), [])

    def test_pending_information_splits_review_kinds(self):
        assessment = {"checks": [
            check("AC-01", "review", review_kind="static_done_external_pending"),
            check("AC-02", "review", review_kind="external_only"),
            check("AC-03", "review"),
            check("AU-01", "pass")]}
        text = "；".join(build_pending_information({"security_level": "C", "protection_demand_level": "普"}, assessment))
        self.assertIn("僅缺部署／政策／動態佐證 1 項", text)
        self.assertIn("外部或制度證據 1 項", text)
        self.assertIn("未分類 1 項", text)

    def test_pending_information_includes_ratio_note(self):
        pending = build_pending_information(
            {"security_level": "C", "protection_demand_level": "普"}, self._assessment(8, 2),
            review_ratio_note="多數控制屬部署層")
        self.assertTrue(any("警示門檻" in p and "多數控制屬部署層" in p for p in pending))


if __name__ == "__main__":
    unittest.main()
