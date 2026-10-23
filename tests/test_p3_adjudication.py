"""P3：真實外部阻斷與錯誤 review 判定的回歸測試，不以合成輸入聲稱掃描品質。"""
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

from analysis_prepare import prepare
from assessment_consistency import consistency_errors
from control_effectiveness import snapshot_fingerprint
from decision_adjudication import (AUDITS, CATEGORIES, _meaningful_static_source,
                                   adjudication_errors, guidance)
from quality_baseline import PROJECT_FILE, load_catalog
from review_queue import build_queue, initialize, load_rules
from review_safety import _write, integrate, report_dir, stage


class P3AdjudicationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cases = {row["id"]: row for row in load_catalog()["cases"]}
        case = self.cases["session-expiry-safe"]
        (self.root / "Case.csproj").write_text(PROJECT_FILE, encoding="utf-8")
        for path, content in case["files"].items():
            (self.root / path).write_text(content, encoding="utf-8")
        with (patch("analysis_prepare.probe_roslyn", return_value={"available": False}),
              patch("analysis_prepare.probe_codegraph", return_value={"available": False})):
            prepare(self.root, "full")
        self.snapshot = json.loads((report_dir(self.root) / "analysis/review-snapshot.json")
                                   .read_text(encoding="utf-8"))
        self.artifact = "正式 Session 絕對逾時政策核定文件"
        self.loc = self.position("SessionValidator.cs", "session.ExpiresAt > now")
        self.review = {
            "id": "AC-01", "status": "review",
            "review_kind": "static_done_external_pending",
            "decision_reason": ("已核對 Session 服務端期限及失效拒絕分支；待確認："
                                + self.artifact),
            "evidence": [{"kind": "source", **self.loc,
                          "description": "已核實控制使用 ExpiresAt 判斷逾期失效"}],
            "execution": {"state": "completed", "methods": ["source_review"],
                          "summary": "已完整追查 Session 發行、登入後驗證及過期拒絕分支",
                          "inspected_paths": case["required_paths"]},
        }
        self.audit = {
            "status": "review",
            "review_kind": "static_done_external_pending",
            "git_revision": self.snapshot["git_revision"],
            "snapshot_fingerprint": snapshot_fingerprint(self.snapshot),
            "static_result": "control_satisfied",
            "static_conclusion": "已檢查 SessionValidator 的過期驗證，過期資料由伺服端拒絕使用",
            "searched_paths": case["required_paths"],
            "static_evidence": [self.loc],
            "external_gap": {
                "category": "organization_policy",
                "artifact": self.artifact,
                "blocking_question": "組織正式核定的逾時上限是否接受目前伺服器設定的期限",
                "why_decisive": "程式碼能證明伺服器會拒絕過期憑證，但無法自行推定組織核定的時限長度",
                "manual_boundary": guidance("AC-01")["manual_boundary"],
            },
            "open_static_questions": [],
        }

    def position(self, name, match):
        lines = (self.root / name).read_text("utf-8").splitlines()
        line = next(i for i, row in enumerate(lines, 1) if match in row)
        return {"path": name, "line_start": line, "line_end": line}

    def check(self, row=None, audit=None):
        if audit is None:
            (self.root / AUDITS).unlink(missing_ok=True)
        else:
            _write(self.root / AUDITS, {self.review["id"]: audit})
        return adjudication_errors(self.root, [self.review if row is None else row])

    def test_all_70_rules_return_mode_aware_review_guidance(self):
        _, rules = load_rules()
        self.assertEqual(len(rules), 70)
        for rule in rules:
            with self.subTest(rule=rule["id"]):
                detail = guidance(rule["id"])
                self.assertIn(detail["mode"], {"static", "hybrid", "external"})
                self.assertEqual(detail["manual_boundary"],
                                 guidance(rule["id"])["manual_boundary"])
                self.assertTrue(detail["required_audit_fields"])
        self.assertIn("organization_policy", CATEGORIES)
        self.assertEqual(guidance("BC-03")["mode"], "external")

    def test_static_part_complete_but_real_external_policy_boundary_permits_review(self):
        self.assertEqual(self.check(audit=copy.deepcopy(self.audit)), [])

    def test_missing_specific_gap_blocks_completed_review(self):
        errors = self.check()
        self.assertTrue(any("P3 尚未說明" in e for e in errors), errors)

    def test_test_only_or_generic_review_is_rejected(self):
        audit = copy.deepcopy(self.audit)
        audit["external_gap"]["artifact"] = "缺少動態測試結果及邊界案例紀錄"
        review = copy.deepcopy(self.review)
        review["decision_reason"] += "；待確認：缺少動態測試結果及邊界案例紀錄"
        errors = self.check(review, audit)
        self.assertIn("不得僅因缺少非必要動態測試", "；".join(errors))
        audit = copy.deepcopy(self.audit)
        audit["external_gap"]["category"] = "test_result"
        self.assertIn("必須明確命名", "；".join(self.check(audit=audit)))

    def test_malformed_external_category_is_reported_without_crashing(self):
        audit = copy.deepcopy(self.audit)
        audit["external_gap"]["category"] = ["organization_policy"]
        errors = self.check(audit=audit)
        self.assertTrue(any("必須明確命名" in x for x in errors), errors)

    def test_real_configuration_value_is_acceptable_not_empty_placeholder(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = root / "appsettings.Production.json"
            config.write_text('{\n  "Session": { "IdleMinutes": 20 }\n}\n', encoding="utf-8")
            item = {"path": config.name, "line_start": 2, "line_end": 2}
            self.assertTrue(_meaningful_static_source(root, item))
            config.write_text("{}\n", encoding="utf-8")
            item["line_start"] = item["line_end"] = 1
            self.assertFalse(_meaningful_static_source(root, item))
            self.assertFalse(_meaningful_static_source(
                root, {"path": config.name, "line_start": 7, "line_end": 7}))

    def test_unfinished_static_work_cannot_hide_under_review(self):
        for mutation in ("inconclusive", "open_question", "no_paths", "no_evidence",
                         "weak_source", "wrong_classification", "bad_line"):
            with self.subTest(mutation=mutation):
                audit = copy.deepcopy(self.audit)
                review = copy.deepcopy(self.review)
                if mutation == "inconclusive":
                    audit["static_result"] = "inconclusive"
                elif mutation == "open_question":
                    audit["open_static_questions"] = ["尚未追查實際驗證呼叫端"]
                elif mutation == "no_paths":
                    audit["searched_paths"] = []
                elif mutation == "no_evidence":
                    audit["static_evidence"] = []
                elif mutation == "weak_source":
                    audit["static_evidence"] = [self.position("SessionRecord.cs",
                                                               "public sealed record")]
                elif mutation == "wrong_classification":
                    audit["review_kind"] = "external_only"
                    review["review_kind"] = "external_only"
                elif mutation == "bad_line":
                    audit["static_evidence"] = [{**self.loc, "line_start": 9999,
                                                "line_end": 9999}]
                self.assertTrue(self.check(row=review, audit=audit))

    def test_wrong_boundary_or_missing_artifact_cannot_justify_review(self):
        for mutation in ("boundary", "artifact", "question", "explanation", "revision", "hash"):
            with self.subTest(mutation=mutation):
                audit = copy.deepcopy(self.audit)
                if mutation == "boundary":
                    audit["external_gap"]["manual_boundary"] = "缺少測試"
                elif mutation == "artifact":
                    audit["external_gap"]["artifact"] = "不存在的部署說明文件"
                elif mutation == "question":
                    audit["external_gap"]["blocking_question"] = "？"
                elif mutation == "explanation":
                    audit["external_gap"]["why_decisive"] = "缺測試"
                elif mutation == "revision":
                    audit["git_revision"] = "stale"
                elif mutation == "hash":
                    audit["snapshot_fingerprint"] = "stale"
                self.assertTrue(self.check(audit=audit))

    def test_genuine_external_p0_cases_are_not_forced_to_pass_or_fail(self):
        for case_id in ("availability-topology-external", "recovery-drill-external"):
            with self.subTest(case=case_id):
                case = self.cases[case_id]
                rule_id = case["rule_id"]
                artifact = case["external_artifact"]
                rule = guidance(rule_id)
                review = {
                    "id": rule_id, "status": "review",
                    "review_kind": "external_only",
                    "decision_reason": "已閱讀現有程式與組態；待確認：" + artifact,
                    "evidence": [],
                    "execution": {"state": "completed", "inspected_paths":
                                  self.cases["session-expiry-safe"]["required_paths"]},
                }
                audit = {
                    "status": "review", "review_kind": "external_only",
                    "git_revision": self.snapshot["git_revision"],
                    "snapshot_fingerprint": snapshot_fingerprint(self.snapshot),
                    "static_result": "external_control",
                    "static_conclusion": "已核對目前可定位的程式碼與設定，但無法由儲存庫確認實際部署或演練狀態",
                    "searched_paths": [],
                    "static_evidence": [],
                    "external_gap": {
                        "category": "deployment" if rule_id == "BC-03" else "operational_record",
                        "artifact": artifact,
                        "blocking_question": "實際環境是否已符合規則要求的外部營運或部署控制",
                        "why_decisive": "此規則要求的是正式環境或已實施的演練，單憑原始碼不足以確認真實狀態",
                        "manual_boundary": rule["manual_boundary"],
                    },
                    "open_static_questions": [],
                }
                _write(self.root / AUDITS, {rule_id: audit})
                self.assertEqual(adjudication_errors(self.root, [review]), [])

    def test_genuine_known_defect_remains_fail_with_finding_not_review(self):
        case = self.cases["session-expiry-bypass"]
        check = copy.deepcopy(self.review)
        check["status"] = "fail"
        check.pop("review_kind")
        check["decision_reason"] = case["rationale"]
        self.assertEqual(self.check(check), [])
        assessment = {"checks": [check], "findings": [
            {"id": "F-AC01", "check_ids": ["AC-01"], "confidence": "confirmed"}
        ]}
        self.assertEqual(consistency_errors(assessment), [])
        check["status"] = "review"
        self.assertTrue(consistency_errors(assessment))

    def test_pending_checks_do_not_get_autoconverted(self):
        c = copy.deepcopy(self.review)
        c["execution"]["state"] = "pending"
        self.assertEqual(self.check(c), [])
        self.assertEqual(c["status"], "review")
        self.assertEqual(c["execution"]["state"], "pending")

    def test_staging_integration_keeps_existing_findings_and_rejects_conflicts(self):
        ruleset, rules = load_rules()
        initialize(self.root, report_dir(self.root), ruleset, rules)
        staged = report_dir(self.root) / "p3-batch.json"
        _write(staged, {"decision_audits": {"AC-01": self.audit}})
        stage(self.root, staged)
        response = integrate(self.root)
        self.assertEqual(response["decision_audits"], 1)
        saved = json.loads((self.root / AUDITS).read_text("utf-8"))
        self.assertEqual(saved["AC-01"], self.audit)
        edited = copy.deepcopy(self.audit)
        edited["static_conclusion"] += "；另已查閱入口來源"
        _write(staged, {"decision_audits": {"AC-01": edited}})
        stage(self.root, staged)
        with self.assertRaisesRegex(ValueError, "P3 判定紀錄衝突"):
            integrate(self.root)

    def test_rule_queue_exposes_p3_guidance_without_replacing_rules(self):
        _, rules = load_rules()
        c = [{"id": r["id"], "status": "review",
              "execution": {"state": "pending", "methods": [], "summary": "尚未執行"}}
             for r in rules]
        queue = build_queue({"checks": c}, rules, 10, detail_id="AC-01")
        self.assertEqual(queue["total"], 70)
        self.assertEqual(queue["next_checks"][0]["decision_adjudication_guidance"]["mode"],
                         "hybrid")


if __name__ == "__main__":
    unittest.main()
