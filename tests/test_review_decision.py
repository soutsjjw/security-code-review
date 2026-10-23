"""70 項判定契約、無效來源證據與外部控制回歸測試。"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from review_decision import load_decision_matrix, decision_quality_errors
from review_queue import load_rules


def row(rid, status="pass", path="Control.cs", start=1, end=1, kind="source", **kwargs):
    return {
        "id": rid, "status": status, "decision_reason": "逐項核對具體設定及其控制效果",
        "evidence": [{
            "kind": kind, "path": path, "line_start": start, "line_end": end,
            "description": "核對可定位的控制語句",
        }],
        "execution": {"state": "completed", "methods": ["source_review"],
                      "summary": "追查實際控制設定與受保護端點"},
        **kwargs,
    }


class DecisionMatrixTests(unittest.TestCase):
    def test_all_70_rules_have_distinct_guidance(self):
        matrix = load_decision_matrix()
        _, rules = load_rules()
        self.assertEqual(set(matrix), {r["id"] for r in rules})
        self.assertEqual(len(matrix), 70)
        self.assertEqual({v["mode"] for v in matrix.values()}, {"static", "hybrid", "external"})
        for rid, info in matrix.items():
            with self.subTest(id=rid):
                self.assertTrue(info["pass_condition"])
                self.assertTrue(info["expected_evidence"])
                self.assertTrue(info["applicability"])

    def test_example_modes(self):
        matrix = load_decision_matrix()
        self.assertEqual(matrix["IN-07"]["mode"], "static")
        self.assertEqual(matrix["AC-01"]["mode"], "hybrid")
        self.assertEqual(matrix["DP-01"]["mode"], "hybrid")
        self.assertEqual(matrix["BC-03"]["mode"], "external")


class EvidenceQualityTests(unittest.TestCase):
    def test_namespace_using_property_and_parameter_are_insufficient(self):
        samples = [
            ("AU-09", "namespace App.Features.Totp;"),
            ("IN-07", "using System.Globalization;"),
            ("PD-02", "public string? IDNo { get; set; }"),
            ("BC-03", "request.RowVersion,"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rid, source in samples:
                with self.subTest(rule=rid):
                    (root / "Control.cs").write_text(source + "\n", encoding="utf-8")
                    errs = decision_quality_errors([row(rid)], source_root=root)
                    self.assertTrue(any("來源證據只含宣告" in e for e in errs), errs)

    def test_real_configuration_branch_is_not_vacuous(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Control.cs").write_text(
                "options.ExpireTimeSpan = TimeSpan.FromMinutes(20);\n"
                "if (user.RefreshTokenExpiryTime <= DateTime.UtcNow) throw new UnauthorizedException();\n",
                encoding="utf-8",
            )
            self.assertEqual(decision_quality_errors([row("AC-01", end=2)], source_root=root), [])

    def test_static_rule_cannot_use_generic_external_pending(self):
        c = row("IN-07", status="review", review_kind="static_done_external_pending")
        self.assertTrue(any("主要可由靜態來源判定" in e for e in decision_quality_errors([c])))

    def test_hybrid_rule_may_have_genuine_external_boundary(self):
        c = row("AC-01", status="review", review_kind="static_done_external_pending")
        c["decision_reason"] = "已確認 Cookie 逾時檢查與入口註冊；尚需確認組織核定的絕對逾時上限"
        self.assertEqual(decision_quality_errors([c]), [])

    def test_external_rule_cannot_pass_using_business_source_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Control.cs").write_text("if (request.QuantityDelta == 0) return Failure();\n", encoding="utf-8")
            errors = decision_quality_errors([row("BC-03")], source_root=root)
            self.assertTrue(any("外部／制度控制" in e for e in errors))

    def test_deployment_artifact_can_support_external_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = root / "deployment.yaml"
            cfg.write_text("replicas: 3\n", encoding="utf-8")
            c = row("BC-03", path="deployment.yaml", kind="configuration")
            self.assertEqual(decision_quality_errors([c], source_root=root), [])

    def test_templates_rejected_without_reading_files(self):
        c = row("AC-01", status="review")
        c["decision_reason"] = ("已完成「Session 逾時自動失效」來源核對；"
                                "目前缺少需補動態測試結果及邊界案例紀錄")
        self.assertTrue(any("制式結論" in e for e in decision_quality_errors([c])))

    def test_noncompleted_rules_not_declared_reviewed(self):
        c = row("PD-02")
        c["execution"]["state"] = "pending"
        c["decision_reason"] = "控制邏輯足以支持本次靜態判定，未確認到可繞過的缺陷"
        self.assertEqual(decision_quality_errors([c]), [])

    def test_vue_source_is_supported_without_assuming_dotnet_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Auth.vue").write_text("const accepted = value && !value.includes('../');\n", encoding="utf-8")
            self.assertEqual(decision_quality_errors([row("IN-07", path="Auth.vue")], source_root=root), [])


if __name__ == "__main__":
    unittest.main()
