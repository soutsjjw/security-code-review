"""安全控制候選、多對多關聯與無效完成證據回歸測試。"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from analysis_candidates import candidate_hits, meaningful_source_excerpt, source_relevant_to_rule
from review_completion import completion_errors
from source_coverage import build_source_coverage
from review_fixture import make_file_review


class CandidateValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.code = (
            "using Microsoft.AspNetCore.Authorization;\n"
            "public class Handler : AuthorizationHandler<MyRequirement> {\n"
            "  // public void ValidateAntiForgeryToken() {}\n"
            "  private IOwnedResource resource;\n"
            "  [ValidateAntiForgeryToken]\n"
            "  public void Save() { }\n"
            "}\n"
        )
        (self.root / "Handler.cs").write_text(self.code, encoding="utf-8")

    def assessment(self, rules=(), exclusions=None):
        row = make_file_review(self.root, "Handler.cs", rules)
        if exclusions is not None:
            row["candidate_exclusions"] = exclusions
        return {
            "checks": [{
                "id": rid,
                "execution": {"state": "completed", "inspected_paths": ["Handler.cs"]},
            } for rid in rules],
            "file_reviews": [row],
        }

    def test_candidate_lookup_is_multi_rule_and_ignores_comments_and_using(self):
        hits = {x["rule_id"]: x for x in candidate_hits("Handler.cs", self.code)}
        self.assertEqual(set(hits), {"AC-04", "AC-08", "IN-03"})
        self.assertEqual(hits["IN-03"]["line"], 5)
        self.assertEqual(candidate_hits("Ignored.vue", self.code), [])
        self.assertEqual(candidate_hits("Helper.cs", "// [ValidateAntiForgeryToken]\nusing Microsoft.AspNetCore.Authorization;"), [])

    def test_ac08_accepts_positive_resource_authorization_control(self):
        self.assertTrue(source_relevant_to_rule(
            "PermissionResourceAuthorizationHandler.cs",
            "src/Infrastructure/Authorization/PermissionResourceAuthorizationHandler.cs",
            ["var allowed = GetMaxAllowedScope(context.User, module, operation);"]
        ))

    def test_ac08_accepts_resource_operation_as_missing_control_evidence(self):
        self.assertTrue(source_relevant_to_rule(
            "DeleteOrderCommandHandler.cs",
            "src/Application/Features/Orders/Commands/DeleteOrder/DeleteOrderCommandHandler.cs",
            ["var order = await context.Orders.FindAsync([request.Id], cancellationToken);",
             "await context.SaveChangesAsync(cancellationToken);"]
        ))
        self.assertTrue(source_relevant_to_rule(
            "GetOrdersQueryHandler.cs",
            "src/Application/Features/Orders/Queries/GetOrders/GetOrdersQueryHandler.cs",
            ["var ordersQuery = _context.Orders",
             ".Where(order => !order.IsDelete);"]
        ))

    def test_ac08_accepts_resource_authorization_wiring_as_chain_evidence(self):
        self.assertTrue(source_relevant_to_rule(
            "AC-08", "src/Infrastructure/DependencyInjection.cs",
            ["builder.Services.AddScoped<IAuthorizationHandler, PermissionResourceAuthorizationHandler>();"]
        ))

    def test_ac08_does_not_treat_unrelated_authorization_or_data_access_as_evidence(self):
        self.assertFalse(source_relevant_to_rule(
            "AC-08", "src/Web/Controllers/OrdersController.cs",
            ["[Authorize]"]
        ))
        self.assertFalse(source_relevant_to_rule(
            "AC-08", "src/Application/Features/User/UserQuery.cs",
            ["var user = await context.Users.FirstOrDefaultAsync(cancellationToken);"]
        ))

    def test_omitted_authorization_and_csrf_candidates_block_completion(self):
        data = self.assessment()
        coverage = build_source_coverage(data, self.root)
        self.assertEqual(coverage["missing_source_file_count"], 1)
        errors = " ".join(coverage["review_integrity_errors"])
        for rid in ("AC-04", "AC-08", "IN-03"):
            self.assertIn(rid, errors)
        self.assertIn("candidate_exclusions", errors)

    def test_multiple_related_rules_pass_integrity(self):
        data = self.assessment(("AC-04", "AC-08", "IN-03"))
        result = build_source_coverage(data, self.root)
        self.assertEqual(result["review_integrity_errors"], [])
        self.assertEqual(result["reviewed_file_rule_ids"]["Handler.cs"],
                         ["AC-04", "AC-08", "IN-03"])

    def test_specific_candidate_exclusion_is_allowed(self):
        exclusions = [{
            "rule_id": "AC-08",
            "reason": "此檔只有型別宣告並未提供實際資源存取入口，已查核呼叫端與實際資源存取控制由其他專責模組承擔。",
        }, {
            "rule_id": "IN-03",
            "reason": "此註記僅存在於測試範例宣告，非可供使用者呼叫的端點；已核對真實路由沒有對應動作。",
        }]
        result = build_source_coverage(self.assessment(("AC-04",), exclusions), self.root)
        self.assertEqual(result["review_integrity_errors"], [])

    def test_candidate_exclusion_must_be_substantive(self):
        exclusions = [{
            "rule_id": "AC-08",
            "reason": "不適用",
        }]
        result = build_source_coverage(self.assessment(("AC-04", "IN-03"), exclusions), self.root)
        self.assertIn("至少 40 字", " ".join(result["review_integrity_errors"]))

    def test_unrelated_file_can_still_have_zero_rules(self):
        (self.root / "Handler.cs").write_text("// 此處沒有實作\n", encoding="utf-8")
        result = build_source_coverage(self.assessment(), self.root)
        self.assertEqual(result["review_integrity_errors"], [])
        self.assertEqual(result["reviewed_file_rule_ids"]["Handler.cs"], [])

    def test_using_only_evidence_does_not_support_completed_pass(self):
        (self.root / "Handler.cs").write_text("using System.Reflection;\n", encoding="utf-8")
        data = self.assessment(("AC-01",))
        data["checks"][0].update({
            "status": "pass",
            "evidence": [{
                "kind": "source", "path": "Handler.cs",
                "line_start": 1, "line_end": 1,
                "description": "已檢查登入權限與登入工作流程",
            }],
        })
        result = build_source_coverage(data, self.root)
        self.assertIn("無效來源片段", " ".join(result["review_integrity_errors"]))

    def test_method_signature_alone_is_not_security_evidence(self):
        (self.root / "Handler.cs").write_text("public async Task SignOutAsync()\n", encoding="utf-8")
        data = self.assessment(("AC-02",))
        data["checks"][0].update({
            "status": "pass", "evidence": [{
                "kind": "source", "path": "Handler.cs",
                "line_start": 1, "line_end": 1,
                "description": "聲稱已有安全登出",
            }],
        })
        result = build_source_coverage(data, self.root)
        self.assertIn("無效來源片段", " ".join(result["review_integrity_errors"]))

    def test_real_control_evidence_is_allowed(self):
        (self.root / "Handler.cs").write_text("options.Cookie.HttpOnly = true;\n", encoding="utf-8")
        data = self.assessment(("CR-06",))
        data["checks"][0].update({
            "status": "pass", "evidence": [{
                "kind": "source", "path": "Handler.cs",
                "line_start": 1, "line_end": 1,
                "description": "檢查 Cookie HttpOnly 設定值",
            }],
        })
        result = build_source_coverage(data, self.root)
        self.assertEqual(result["review_integrity_errors"], [])

    def test_class_declaration_and_builder_bootstrap_are_weak(self):
        self.assertFalse(meaningful_source_excerpt(
            "Service.cs", ["public sealed class Service {}"]))
        self.assertFalse(meaningful_source_excerpt(
            "Program.cs", ["var builder = WebApplication.CreateBuilder(args);"]))
        self.assertTrue(meaningful_source_excerpt(
            "Program.cs", ["app.UseHsts();"]))

    def test_queue_shows_multiple_candidates_for_unreviewed_source(self):
        from review_queue import build_queue, load_rules
        _, rules = load_rules()
        data = {
            "checks": [{"id": rule["id"], "execution": {"state": "pending"}}
                       for rule in rules],
            "file_reviews": [],
        }
        queue = build_queue(data, rules, 10, source_root=self.root, compact=True)
        self.assertEqual(queue["next_source_candidates"][0]["path"], "Handler.cs")
        self.assertEqual(set(queue["next_source_candidates"][0]["rule_ids"]),
                         {"AC-04", "AC-08", "IN-03"})

    def test_review_generic_gap_is_rejected_but_specific_gap_allowed(self):
        check = {
            "id": "IN-06", "status": "review",
            "execution": {
                "state": "completed", "methods": ["source_review"],
                "summary": "已檢閱上傳檔案型別及伺服端限制設定。",
            },
            "evidence": [{
                "kind": "source", "path": "Upload.cs", "line_start": 12,
                "line_end": 24, "description": "已核對上傳限制",
            }],
            "decision_reason": "已檢查上傳流程，但仍待確認的外部證據包括部署設定、正式政策、運作紀錄或動態測試。",
        }
        self.assertIn("制式外部證據清單", " ".join(completion_errors([check])))
        check["decision_reason"] = "已確認副檔名及大小檢查，但缺少反向代理的實際最大請求大小設定截圖。"
        self.assertEqual(completion_errors([check]), [])


if __name__ == "__main__":
    unittest.main()
