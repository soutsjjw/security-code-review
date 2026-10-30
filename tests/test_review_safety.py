"""六項 P0：跨檔候選、全專案規則、隔離暫存、閉包、衝突、版本回歸。"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/lib"))

from analysis_prepare import prepare
from review_safety import _write, integrate, refresh_snapshot, safety_errors, stage
from review_snapshot import CLOSURES, closure_errors, report_dir, rule_scopes, scope_tasks, snapshot_errors


class P0ReviewSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "Api.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup>'
            '<TargetFramework>net8.0</TargetFramework></PropertyGroup>'
            '<ItemGroup><ProjectReference Include="Auth/Auth.csproj" /></ItemGroup></Project>',
            encoding="utf-8")
        (self.root / "Auth").mkdir()
        (self.root / "Auth/Auth.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
            '<TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>',
            encoding="utf-8")
        (self.root / "Program.cs").write_text(
            'services.AddScoped<IIdentity, IdentityService>();\n'
            'builder.Configuration.GetSection("Jwt");\n'
            'app.UseAuthorization();\napp.UseAuthentication();\n',
            encoding="utf-8")
        (self.root / "Auth/IdentityService.cs").write_text(
            'public interface IIdentity {}\n'
            'public class IdentityService : IIdentity { }\n'
            '[Authorize] public class SecureEndpoint {}\n',
            encoding="utf-8")
        (self.root / "appsettings.json").write_text(
            '{"Jwt":{"Issuer":"local"}}', encoding="utf-8")
        with patch("analysis_prepare.probe_roslyn", return_value={"available": False}), \
             patch("analysis_prepare.probe_codegraph", return_value={"available": False}):
            prepare(self.root)
        self.report = report_dir(self.root)
        rules = json.loads((ROOT / "rules.json").read_text("utf-8"))["rules"]
        self.assessment = {"checks": [
            {"id": r["id"], "status": "review", "applicability_reason": "待審查",
             "decision_reason": "尚未完成", "evidence": [],
             "reviewer": "test", "execution": {"state": "pending", "methods": [], "summary": "未執行"}}
            for r in rules], "findings": [], "file_reviews": []}
        _write(self.report / "assessment.json", self.assessment)
        # 保留對舊版審查閉包的回歸測試；新交易鏈另由
        # test_evidence_integrity.py 驗證，避免直接寫檔繞過新版整合流程。
        index_path = self.report / "analysis/structure-index.json"
        index = json.loads(index_path.read_text(encoding="utf-8"))
        index.pop("evidence_integrity_version", None)
        index.pop("cross_file_evidence_version", None)  # 既有閉包格式回歸測試
        _write(index_path, index)

    def test_typed_links_include_di_configuration_middleware_endpoint_and_projects(self):
        index = json.loads((self.report / "analysis/structure-index.json").read_text("utf-8"))
        edges = index["typed_relationships"]
        kinds = {x["kind"] for x in edges}
        self.assertGreaterEqual(len(kinds), 5)
        self.assertTrue({"di_registration", "configuration_reference", "middleware_pipeline",
                         "endpoint_authorization", "project_reference"} <= kinds)
        self.assertTrue(any(x["kind"] == "di_registration" and
                            x["target"] == "Auth/IdentityService.cs" for x in edges))
        self.assertTrue(all(x["resolution"] == "candidate_only" for x in edges))

    def test_all_seventy_have_scope_even_without_search_hits(self):
        tasks = scope_tasks(self.root)
        self.assertEqual(len(tasks), 70)
        self.assertEqual(len(rule_scopes()), 70)
        by_id = {task["rule_id"]: task for task in tasks}
        self.assertEqual(by_id["DP-01"]["scope"], "project")
        self.assertTrue(by_id["DP-01"]["project_responsibility_check"])
        self.assertTrue(by_id["DP-01"]["needs_closure"])

    def test_source_changes_and_git_revision_invalidate_snapshot(self):
        self.assertEqual(snapshot_errors(self.root), [])
        (self.root / "Other.cs").write_text("class Other {}", encoding="utf-8")
        self.assertTrue(snapshot_errors(self.root))
        with patch("analysis_prepare.probe_roslyn", return_value={"available": False}), \
             patch("analysis_prepare.probe_codegraph", return_value={"available": False}):
            with self.assertRaisesRegex(ValueError, "快照"):
                prepare(self.root, "incremental")
        refresh_snapshot(self.root)
        self.assertTrue(any("索引" in error for error in snapshot_errors(self.root)))
        with patch("analysis_prepare.probe_roslyn", return_value={"available": False}), \
             patch("analysis_prepare.probe_codegraph", return_value={"available": False}):
            prepare(self.root, "full")
        self.assertEqual(snapshot_errors(self.root), [])
        with patch("review_snapshot.git_revision", return_value="different-revision"):
            self.assertTrue(snapshot_errors(self.root))

    def test_crossfile_and_project_closure_block_early_completion(self):
        cross = next(x for x in self.assessment["checks"] if x["id"] == "AC-01")
        project = next(x for x in self.assessment["checks"] if x["id"] == "DP-01")
        cross.update(status="pass", execution={"state": "completed", "methods": ["人工來源檢查"],
                                                "summary": "已檢核來源"})
        project.update(status="review", execution={"state": "completed", "methods": ["人工責任核對"],
                                                   "summary": "已查核依賴"})
        errors = closure_errors(self.root, self.assessment)
        self.assertIn("AC-01", str(errors))
        self.assertIn("DP-01", str(errors))
        edges = json.loads((self.report / "analysis/structure-index.json").read_text("utf-8"))["typed_relationships"]
        ac_ids = [e["id"] for e in edges if e.get("source") in {"Program.cs", "Auth/IdentityService.cs"}
                  or e.get("target") in {"Program.cs", "Auth/IdentityService.cs"}]
        dp_ids = [e["id"] for e in edges if e.get("source") in {"Api.csproj", "Auth/Auth.csproj"}
                  or e.get("target") in {"Api.csproj", "Auth/Auth.csproj"}]
        _write(self.report / CLOSURES, {
            "AC-01": {
                "status": "pass", "summary": "已追查登入到驗證鏈並確認關聯設定與逾期驗證",
                "examined_paths": ["Program.cs", "Auth/IdentityService.cs"],
                "control_owner": "IdentityService",
                "search_summary": "已檢查 Program 與 Identity 服務及引用的設定檔",
                "examined_relationship_ids": ac_ids, "open_issues": []},
            "DP-01": {
                "status": "review", "summary": "已核對所有 csproj 與集中套件版本但需外部弱點資料",
                "examined_paths": ["Api.csproj", "Auth/Auth.csproj"],
                "control_owner": "套件管理與維運責任",
                "search_summary": "已檢查 Api 與 Auth 兩個專案的套件參考、版本設定、集中套件清單與弱點掃描工件位置",
                "examined_relationship_ids": dp_ids, "open_issues": []},
        })
        self.assertEqual(closure_errors(self.root, self.assessment), [])
        # P1 結案成功仍不代表 P2 控制有效性已獲證明。
        self.assertIn("AC-01: P2 缺少", str(safety_errors(self.root, self.assessment)))

    def test_stage_does_not_touch_assessment_and_conflict_is_not_silent(self):
        original = (self.report / "assessment.json").read_bytes()
        updated = dict(self.assessment["checks"][0])
        updated["execution"] = {"state": "completed", "methods": ["人工分析"], "summary": "已有來源查核"}
        payload = self.root / "stage-input.json"
        # 暫存檔必須放在排除來源的 reports 資料夾，以免影響工作樹快照。
        payload = self.report / "draft.json"
        _write(payload, {"checks": [updated]})
        stage(self.root, payload)
        self.assertEqual((self.report / "assessment.json").read_bytes(), original)
        # 此案例只隔離測試 Stage/衝突行為；完成證據守門由下方專屬測試驗證。
        with patch("batch_evidence_gate.completion_transition_errors", return_value=[]):
            result = integrate(self.root)
        self.assertEqual(result["checks"], 1)
        self.assertEqual(json.loads((self.report / "assessment.json").read_text(encoding="utf-8"))["checks"][0]
                         ["execution"]["state"], "completed")
        changed = dict(updated)
        changed["status"] = "fail"
        _write(payload, {"checks": [changed]})
        stage(self.root, payload)
        with self.assertRaisesRegex(ValueError, "規則不同"):
            integrate(self.root)

    def test_integrate_rejects_unrelated_new_file_review_without_writing(self):
        from review_fixture import make_file_review
        original = (self.report / "assessment.json").read_bytes()
        file_row = make_file_review(self.root, "Program.cs", ["AC-04"])
        file_row["rule_reviews"][0]["line_start"] = 1
        file_row["rule_reviews"][0]["line_end"] = 1
        # 第 1 行只是 DI 型別註冊，不能冒充 AC-04 的控制執行證據。
        updated = dict(next(c for c in self.assessment["checks"] if c["id"] == "AC-04"))
        updated["execution"] = {
            "state": "completed", "methods": ["實際來源核對"],
            "summary": "已核對逐檔安全控制", "inspected_paths": ["Program.cs"],
        }
        draft = self.report / "bad-batch.json"
        _write(draft, {"checks": [updated], "file_reviews": [file_row]})
        stage(self.root, draft)
        with self.assertRaisesRegex(ValueError, "批次逐檔證據不合格"):
            integrate(self.root)
        self.assertEqual((self.report / "assessment.json").read_bytes(), original)


    def test_new_completed_requires_closure_before_commit(self):
        original = (self.report / "assessment.json").read_bytes()
        check = dict(next(c for c in self.assessment["checks"] if c["id"] == "AC-01"))
        check.update(
            status="pass", decision_reason="已檢查實際授權與逾時處理分支",
            evidence=[{"kind": "source", "path": "Program.cs", "line_start": 3, "line_end": 3}],
            execution={"state": "completed", "methods": ["read_source"],
                       "summary": "已查核實際控制執行與需要的來源關聯。"},
        )
        draft = self.report / "completion-no-closure.json"
        _write(draft, {"checks": [check]})
        stage(self.root, draft)
        with self.assertRaisesRegex(ValueError, "新完成規則證據未通過守門.*缺少 cross_file"):
            integrate(self.root)
        self.assertEqual((self.report / "assessment.json").read_bytes(), original)
        self.assertFalse((self.report / CLOSURES).exists())

    def test_new_completed_requires_q2_control_trace(self):
        index_path = self.report / "analysis/structure-index.json"
        index = json.loads(index_path.read_text(encoding="utf-8"))
        index["cross_file_evidence_version"] = 1
        _write(index_path, index)
        check = dict(next(c for c in self.assessment["checks"] if c["id"] == "AC-01"))
        check.update(
            status="pass",
            execution={"state": "completed", "methods": ["read_source"],
                       "summary": "已核對入口與來源控制分支"},
        )
        closure = {"status": "pass", "summary": "已核對所有入口與組態間的控制責任",
                   "examined_paths": ["Program.cs"], "control_owner": "Authentication",
                   "search_summary": "已檢查全部入口、登入控制及中介軟體設定",
                   "examined_relationship_ids": [], "dismissed_relationships": {},
                   "callsite_reviews": {}, "open_issues": []}
        draft = self.report / "completion-no-trace.json"
        _write(draft, {"checks": [check], "closures": {"AC-01": closure}})
        stage(self.root, draft)
        with self.assertRaisesRegex(ValueError, "Q2 缺少實際入口"):
            integrate(self.root)
        self.assertFalse((self.report / CLOSURES).exists())

    def test_new_completed_requires_p2_q3_and_p3(self):
        for rid, status, marker in (
            ("AC-01", "fail", "Q3 缺少"),
            ("AC-01", "pass", "P2 缺少"),
            ("DP-01", "review", "P3 尚未說明"),
        ):
            with self.subTest(rule=rid, status=status):
                check = dict(next(c for c in self.assessment["checks"] if c["id"] == rid))
                check.update(status=status, execution={"state": "completed",
                            "methods": ["read_source"], "summary": "已核對安全控制來源與執行路徑"})
                draft = self.report / f"completion-{rid}-{status}.json"
                _write(draft, {"checks": [check]})
                stage(self.root, draft)
                with self.assertRaisesRegex(ValueError, marker):
                    integrate(self.root)
                # Clearing unsuccessful staged input here is fixture cleanup only.
                for pending in (self.report / "analysis/staged").glob("*.json"):
                    pending.unlink()
        self.assertFalse((self.report / "analysis/rule-closures.json").exists())

    def test_preexisting_invalid_completed_can_repair_sidecars_in_batches(self):
        check = next(c for c in self.assessment["checks"] if c["id"] == "AC-01")
        check["execution"] = {"state": "completed", "methods": ["read_source"],
                              "summary": "舊證據尚未完整核對"}
        _write(self.report / "assessment.json", self.assessment)
        draft = self.report / "partial-legacy-repair.json"
        _write(draft, {"closures": {"AC-01": {
            "status": "review",
            "summary": "先登記實際查核中找到的負責元件，後續批次補齊來源佐證"
        }}})
        stage(self.root, draft)
        self.assertEqual(integrate(self.root)["closures"], 1)
        self.assertEqual(json.loads((self.report / "assessment.json").read_text("utf-8"))
                         ["checks"][0]["execution"]["state"], "completed")
        self.assertTrue(safety_errors(self.root, self.assessment))

    def test_finding_duplicates_collapse_without_erasing_existing(self):
        evidence = [{"path": "Program.cs", "line_start": 3, "line_end": 4}]
        f1 = {"id": "F-1", "title": "不安全 Middleware 順序", "check_ids": ["AC-04"],
              "evidence": evidence}
        f2 = dict(f1, id="F-2")
        draft = self.report / "draft-findings.json"
        _write(draft, {"findings": [f1, f2]})
        stage(self.root, draft)
        result = integrate(self.root)
        self.assertEqual(result["findings"], 1)
        assessment = json.loads((self.report / "assessment.json").read_text("utf-8"))
        self.assertEqual([f["id"] for f in assessment["findings"]], ["F-1"])


if __name__ == "__main__":
    unittest.main()
