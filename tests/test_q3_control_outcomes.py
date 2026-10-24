"""完成的 Fail／Review 安全控制有效性：真實來源、Finding 及外部邊界回歸測試。"""
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
from control_effectiveness import (REQUIRED_SCENARIOS, VERIFICATIONS,
                                   guidance, snapshot_fingerprint, verification_errors)
from quality_baseline import PROJECT_FILE, load_catalog
from review_safety import _write, report_dir


class ControlOutcomeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.catalog = {case["id"]: case for case in load_catalog()["cases"]}
        self.prepare_case("session-expiry-bypass")

    def prepare_case(self, case_id):
        case = self.catalog[case_id]
        (self.root / "Case.csproj").write_text(PROJECT_FILE, encoding="utf-8")
        for name, value in case["files"].items():
            (self.root / name).write_text(value, encoding="utf-8")
        with patch("analysis_prepare.probe_roslyn", return_value={"available": False}), \
             patch("analysis_prepare.probe_codegraph", return_value={"available": False}):
            prepare(self.root, "full")
        self.snapshot = json.loads((report_dir(self.root) / "analysis/review-snapshot.json")
                                   .read_text(encoding="utf-8"))
        self.case = case

    def loc(self, path, fragment):
        rows = (self.root / path).read_text(encoding="utf-8").splitlines()
        i = next(i for i, row in enumerate(rows, 1) if fragment in row)
        return {"path": path, "line_start": i, "line_end": i}

    def setup_fail(self):
        entry = self.loc("SessionEndpoint.cs", "_validator.IsActive(session, now)")
        defect = self.loc("SessionValidator.cs", "session is not null;")
        record = {
            "status": "fail",
            "git_revision": self.snapshot["git_revision"],
            "snapshot_fingerprint": snapshot_fingerprint(self.snapshot),
            "source_hashes": self.snapshot["source_hashes"],
            "entry_points": [entry],
            "failure_points": [defect],
            "protected_operations": [entry],
            "failure_mode": "ineffective_enforcement",
            "failure_reason": "驗證器只檢查 session 非 null，未讀取 ExpiresAt，過期 Session 仍能回傳私人資料",
            "search_summary": "已核對 SessionEndpoint 的資料存取、SessionValidator 的驗證條件及 SessionRecord 到期欄位",
            "bypass_scenarios": [{
                "scenario": "expired_session",
                "outcome": "confirmed_vulnerability",
                "reason": "重送已過期且非 null 的 Session 時，IsActive 仍會回傳 true，直接繞過期限控制",
                "evidence": [defect, entry],
            }],
            "open_issues": [],
        }
        check = {
            "id": "AC-01", "status": "fail", "finding_ids": ["F-AC01"],
            "evidence": [{"kind": "source", **defect}],
            "execution": {"state": "completed", "inspected_paths": self.case["required_paths"]},
        }
        finding = {"id": "F-AC01", "check_ids": ["AC-01"],
                   "title": "逾期 Session 可繼續使用", "evidence": [defect]}
        _write(report_dir(self.root) / "assessment.json",
               {"checks": [check], "findings": [finding]})
        return check, record

    def setup_review(self):
        self.root = self.root / "review-case"
        self.root.mkdir()
        self.prepare_case("session-expiry-safe")
        safe = self.case
        entry = self.loc("SessionEndpoint.cs", "_validator.IsActive(session, now)")
        control = self.loc("SessionValidator.cs", "session.ExpiresAt > now")
        operation = self.loc("SessionEndpoint.cs", '"private-data"')
        artifact = "正式已適用的組織 Session 期限核定條款"
        check = {
            "id": "AC-01", "status": "review", "review_kind": "static_done_external_pending",
            "evidence": [{"kind": "source", **control}],
            "execution": {"state": "completed", "inspected_paths": safe["required_paths"]},
        }
        record = {
            "status": "review",
            "git_revision": self.snapshot["git_revision"],
            "snapshot_fingerprint": snapshot_fingerprint(self.snapshot),
            "source_hashes": self.snapshot["source_hashes"],
            "entry_points": [entry],
            "enforcement_points": [control],
            "protected_operations": [operation],
            "control_condition": "登入票據在伺服端逐次比對 ExpiresAt，嚴格大於 now 才允許讀取敏感內容",
            "failure_behavior": "過期或缺少票據時 IsActive 回傳 false，Endpoint 不回傳私人資料",
            "search_summary": "已查核 Endpoint 入口、Validator 條件、SessionRecord 時效欄位及不同設定來源",
            "external_gap_artifact": artifact,
            "bypass_scenarios": [{
                "scenario": key,
                "outcome": "external_boundary" if key == "configuration_override" else "blocked",
                "reason": ("實際逾期或旁路由來源證實會拒絕；但組織正式核定的最長期限 "
                           "是否低於程式碼期限仍須已適用政策確認"),
                "evidence": [entry, control, operation],
            } for key in REQUIRED_SCENARIOS["AC-01"]],
            "open_issues": [],
        }
        _write(report_dir(self.root) / "analysis/decision-audits.json", {
            "AC-01": {"static_result": "control_satisfied",
                      "external_gap": {"artifact": artifact}}
        })
        _write(report_dir(self.root) / "assessment.json",
               {"checks": [check], "findings": []})
        return check, record

    def evaluate(self, check, record):
        _write(self.root / VERIFICATIONS, {"AC-01": record} if record is not None else {})
        return verification_errors(self.root, [check])

    def test_all_seventy_have_mode_aware_outcome_guidance(self):
        matrix = load_catalog()
        self.assertEqual(len(matrix["cases"]), 16)
        rules = json.loads((ROOT / "rules.json").read_text(encoding="utf-8"))["rules"]
        self.assertEqual(len(rules), 70)
        for rule in rules:
            info = guidance(rule["id"])
            self.assertTrue(info["required_for_fail"])
            self.assertTrue(info["required_for_review"])

    def test_known_expiry_bypass_fail_requires_finding_and_source_proof(self):
        check, record = self.setup_fail()
        self.assertEqual(self.evaluate(check, record), [])

    def test_real_policy_blocking_review_requires_control_and_bypass_proofs(self):
        check, record = self.setup_review()
        self.assertEqual(self.evaluate(check, record), [])

    def test_fail_cannot_hide_unconfirmed_or_invalid_exploit(self):
        check, record = self.setup_fail()
        bad = copy.deepcopy(record)
        bad["bypass_scenarios"][0]["outcome"] = "blocked"
        self.assertIn("至少一條具體確認", "；".join(self.evaluate(check, bad)))
        bad = copy.deepcopy(record)
        bad["failure_points"] = bad["entry_points"]
        self.assertIn("未連結正式檢核", "；".join(self.evaluate(check, bad)))
        bad = copy.deepcopy(record)
        bad["source_hashes"]["SessionValidator.cs"] = "stale"
        self.assertIn("SHA256", "；".join(self.evaluate(check, bad)))
        bad = copy.deepcopy(record)
        bad["open_issues"] = ["另一條工作階段路徑尚未追查"]
        self.assertIn("尚未完成", "；".join(self.evaluate(check, bad)))

    def test_fail_with_missing_or_unrelated_finding_must_not_complete(self):
        check, record = self.setup_fail()
        bad = copy.deepcopy(check)
        bad["finding_ids"] = []
        self.assertIn("Finding", "；".join(self.evaluate(bad, record)))
        bad = copy.deepcopy(check)
        bad["finding_ids"] = ["unrelated"]
        self.assertIn("Finding", "；".join(self.evaluate(bad, record)))

    def test_review_cannot_hide_unresolved_scenario_or_missing_boundary(self):
        check, record = self.setup_review()
        bad = copy.deepcopy(record)
        bad["bypass_scenarios"][0]["outcome"] = "unresolved"
        self.assertIn("不可為未核對", "；".join(self.evaluate(check, bad)))
        bad = copy.deepcopy(record)
        bad["bypass_scenarios"].pop()
        self.assertIn("尚未查證必要", "；".join(self.evaluate(check, bad)))
        bad = copy.deepcopy(record)
        for row in bad["bypass_scenarios"]:
            row["outcome"] = "blocked"
        self.assertIn("真正外部證據", "；".join(self.evaluate(check, bad)))
        bad = copy.deepcopy(record)
        bad["external_gap_artifact"] = "AC-01-deployment-or-policy-evidence"
        self.assertIn("未連結", "；".join(self.evaluate(check, bad)))

    def test_external_only_and_old_index_not_forced_to_invent_source(self):
        check = {"id": "BC-03", "status": "review", "review_kind": "external_only",
                 "execution": {"state": "completed"}}
        self.assertEqual(self.evaluate(check, None), [])
        check["status"] = "fail"
        self.assertEqual(self.evaluate(check, None), [])
        check, record = self.setup_fail()
        path = report_dir(self.root) / "analysis/structure-index.json"
        index = json.loads(path.read_text(encoding="utf-8"))
        index.pop("control_outcome_version", None)
        _write(path, index)
        self.assertEqual(self.evaluate(check, None), [])

    def test_unfinished_checks_are_not_forced_into_a_result(self):
        check, _ = self.setup_fail()
        check["execution"]["state"] = "pending"
        self.assertEqual(self.evaluate(check, None), [])


if __name__ == "__main__":
    unittest.main()
