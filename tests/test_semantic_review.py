"""實際控制邏輯、逐檔證據與重新審查佇列回歸案例。"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from analysis_candidates import (candidate_hits, has_executable_control,
                                 meaningful_source_excerpt, source_relevant_to_rule)
from analysis_prepare import cross_file_call_hints
from review_fixture import make_file_review
from review_queue import build_queue, load_rules
from source_coverage import build_source_coverage


class SemanticSecurityReviewTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def write(self, path: str, content: str) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def assess(self, path: str, rid: str, *, status: str = "pass",
               rule_line: int = 1, evidence_line: int = 1):
        row = make_file_review(self.root, path, [rid])
        row["rule_reviews"][0]["line_start"] = rule_line
        row["rule_reviews"][0]["line_end"] = rule_line
        return {
            "checks": [{
                "id": rid, "status": status,
                "execution": {"state": "completed", "inspected_paths": [path]},
                "evidence": [{
                    "kind": "source", "path": path,
                    "line_start": evidence_line, "line_end": evidence_line,
                    "description": "已核對來源中的安全控制與相關執行結果",
                }],
            }],
            "file_reviews": [row],
        }

    def test_validation_behaviour_cannot_claim_declaration_only(self):
        source = (
            "public class ValidationBehaviour<TRequest> {\n"
            "  public async Task Handle() {\n"
            "    var results = await validator.ValidateAsync(context, cancellationToken);\n"
            "    if (results.Errors.Any()) throw new ValidationException(results.Errors);\n"
            "  }\n"
            "}\n"
        )
        self.write("ValidationBehaviour.cs", source)
        hits = {hit["rule_id"] for hit in candidate_hits("ValidationBehaviour.cs", source)}
        self.assertIn("IN-05", hits)
        self.assertTrue(has_executable_control("IN-05", "ValidationBehaviour.cs", source))
        data = self.assess("ValidationBehaviour.cs", "IN-05",
                           rule_line=3, evidence_line=3)
        data["file_reviews"][0]["rule_reviews"] = []
        data["file_reviews"][0]["category_screening"]["IN"]["rule_ids"] = []
        data["checks"][0]["execution"]["inspected_paths"] = []
        data["file_reviews"][0]["candidate_exclusions"] = [{
            "rule_id": "IN-05",
            "reason": "這支程式只有型別宣告沒有程式邏輯，驗證操作已核對屬於其他的專責模組，故沒有直接控制責任。",
        }]
        coverage = build_source_coverage(data, self.root)
        self.assertIn("排除理由聲稱沒有控制邏輯", str(coverage["review_integrity_errors"]))

    def test_in06_using_and_au09_fields_not_sufficient(self):
        self.assertFalse(meaningful_source_excerpt(
            "ProductImageValidator.cs", ["using Microsoft.AspNetCore.Http;"]))
        self.assertFalse(meaningful_source_excerpt(
            "AccountController.cs", ["private readonly UserManager<ApplicationUser> _userManager;"]))
        self.assertFalse(source_relevant_to_rule(
            "AU-09", "AccountController.cs", ["private readonly IJwtTokenService _jwtTokenService;"]))
        self.assertTrue(source_relevant_to_rule(
            "IN-06", "ProductImageValidator.cs", ["if (upload.Length > limit) throw new ValidationException();"]))

    def test_file_level_rule_review_rejects_weak_evidence_even_if_check_has_valid_evidence(self):
        source = "using Microsoft.AspNetCore.Http;\nif (upload.Length > limit) throw new ValidationException();\n"
        self.write("ProductImageValidator.cs", source)
        data = self.assess("ProductImageValidator.cs", "IN-06", rule_line=1, evidence_line=2)
        coverage = build_source_coverage(data, self.root)
        self.assertIn("rule_reviews 第 1-1 行只有宣告", str(coverage["review_integrity_errors"]))
        data["file_reviews"][0]["rule_reviews"][0].update(line_start=2, line_end=2)
        coverage = build_source_coverage(data, self.root)
        self.assertEqual(coverage["review_integrity_errors"], [])

    def test_password_and_personal_data_pass_require_relevant_operations(self):
        samples = [
            ("AU-01", "public string ConfirmEmailTokenUrl { get; set; } = \"\";"),
            ("AU-08", "private readonly UserManager<ApplicationUser> _userManager;"),
            ("PD-07", "private readonly IJwtTokenService _jwtTokenService;"),
            ("DP-01", "<ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>"),
            ("DP-04", "<ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>"),
            ("SI-01", "\"remoteUser\": \"vscode\""),
        ]
        for rid, snippet in samples:
            with self.subTest(rule=rid):
                path = "Directory.Packages.props" if rid.startswith("DP") else (
                    ".devcontainer/devcontainer.json" if rid == "SI-01" else "IdentitySettings.cs")
                self.assertFalse(source_relevant_to_rule(rid, path, [snippet]))

    def test_actual_password_setting_is_relevant_but_not_auto_pass(self):
        self.assertTrue(source_relevant_to_rule("AU-01", "IdentitySettings.cs",
                                                ["options.Password.RequiredLength = 12;"]))
        self.assertTrue(source_relevant_to_rule("AU-08", "Hasher.cs",
                                                ["return hasher.HashPassword(user, password);"]))
        self.assertTrue(source_relevant_to_rule("PD-07", "Service.cs",
                                                ["await userManager.DeleteAsync(user);"]))

    def test_repeat_candidate_exclusion_boilerplate_is_rejected(self):
        source = "class Handler : AuthorizationHandler<Req> {}\n"
        rows = []
        for i in range(40):
            path = f"Handler{i}.cs"
            self.write(path, source)
            row = make_file_review(self.root, path)
            row["candidate_exclusions"] = [{
                "rule_id": "AC-04",
                "reason": "確認授權控制實作後，此檔只保留控制責任的宣告，實際呼叫由其他模組提供，故排除此規則直接適用。",
            }]
            rows.append(row)
        result = build_source_coverage({"checks": [], "file_reviews": rows}, self.root)
        self.assertIn("候選排除理由模板", str(result["review_integrity_errors"]))

    def test_cross_file_call_hint_never_claims_semantic_binding(self):
        files = {
            "a.cs": {
                "methods": [{"name": "Handle", "line": 1}],
                "calls": [{"called_method": "ValidateAsync", "name": "validator.ValidateAsync",
                           "receiver": "validator", "containing_method": "Handle", "line": 3}],
            },
            "b.cs": {
                "methods": [{"name": "ValidateAsync", "line": 5, "containing_type": "MyValidator"}],
                "calls": [],
            },
        }
        hints = cross_file_call_hints(files)
        self.assertEqual(hints["a.cs"][0]["possible_targets"][0]["path"], "b.cs")
        self.assertEqual(hints["a.cs"][0]["resolution"], "name_only_ambiguous")
        self.assertNotIn("b.cs", hints)

    def test_all_completed_but_weak_proof_resurfaces_in_next_checks(self):
        _, rules = load_rules()
        self.write("Auth.cs", "using System.Reflection;\n")
        checks = [{
            "id": r["id"], "status": "na",
            "execution": {"state": "completed", "methods": ["manual_review"],
                          "summary": "已核對規則適用性並完成來源及設定逐項檢閱。",
                          "inspected_paths": []},
        } for r in rules]
        checks[0].update({
            "status": "pass",
            "evidence": [{"kind": "source", "path": "Auth.cs",
                          "line_start": 1, "line_end": 1, "description": "已核對授權相關控制"}],
        })
        checks[0]["execution"]["inspected_paths"] = ["Auth.cs"]
        row = make_file_review(self.root, "Auth.cs", ["AC-01"])
        data = {"checks": checks, "file_reviews": [row], "findings": [{"id": "F-1"}]}
        queue = build_queue(data, rules, 10, source_root=self.root, compact=True)
        self.assertEqual(queue["completed"], 70)
        self.assertFalse(queue["ready_for_report"])
        self.assertIn("AC-01", queue["recheck_rule_ids"])
        self.assertEqual(queue["next_checks"][0]["id"], "AC-01")
        self.assertEqual(queue["findings_saved"], 1)


if __name__ == "__main__":
    unittest.main()
