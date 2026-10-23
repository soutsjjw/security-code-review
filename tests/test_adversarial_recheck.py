"""單代理反向複核的機械完整性回歸測試；合成評分資料不是 Agent 審查結果。"""
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

from adversarial_recheck import (BASELINE, REVIEWS, SNAPSHOT, INDEX, digest,
                                 guidance, progress, begin_second_pass, second_pass_errors)
from control_effectiveness import snapshot_fingerprint
from review_decision import load_decision_matrix
from review_safety import _write, stage, integrate, report_dir
from quality_baseline import load_catalog, PROJECT_FILE


class AdversarialSecondPassTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        case = next(x for x in load_catalog()["cases"] if x["id"] == "idor-owner-checked")
        (self.root / "Case.csproj").write_text(PROJECT_FILE, encoding="utf-8")
        for path, source in case["files"].items():
            (self.root / path).write_text(source, encoding="utf-8")
        self.loc = self.location("OrderService.cs", "_repository.FindByOwner(id, userId)")
        self.snapshot = {"schema_version": 1, "git_revision": "synthetic-test-revision",
                         "source_hashes": {path: "synthetic-sha-"+path for path in case["files"]},
                         "excluded_paths": []}
        _write(self.root / SNAPSHOT, self.snapshot)
        _write(self.root / INDEX, {"schema_version": 6,
               "adversarial_second_pass_version": 1, "source_hashes": self.snapshot["source_hashes"]})
        self.rules = load_decision_matrix()
        self.checks = [
            {"id": rid, "status": "na", "applicability_reason": "合成單元測試無適用條件",
             "execution": {"state": "completed", "inspected_paths": ["OrderService.cs"]}}
            for rid in self.rules
        ]
        self.check("AC-08")["status"] = "pass"
        self.assessment = {"checks": self.checks, "findings": []}
        self.baseline = {"schema_version": 1,
                         "snapshot_fingerprint": snapshot_fingerprint(self.snapshot),
                         "checks": {c["id"]: {"status": c["status"], "digest": digest(c)}
                                    for c in self.checks}}
        _write(self.root / BASELINE, self.baseline)
        self.records = {c["id"]: self.make_record(c) for c in self.checks}
        _write(self.root / REVIEWS, self.records)

    def location(self, name, needle):
        lines = (self.root / name).read_text("utf-8").splitlines()
        line = next(i for i, line in enumerate(lines, 1) if needle in line)
        return {"kind": "source", "path": name, "line_start": line, "line_end": line}

    def check(self, rid):
        return next(c for c in self.checks if c["id"] == rid)

    def make_record(self, check):
        rid, status = check["id"], check["status"]
        hypothesis_count = guidance(rid)["required_hypotheses"]
        result = {"pass": "blocked", "fail": "confirmed_vulnerability",
                  "review": "external_boundary", "na": "not_applicable"}[status]
        return {
            "baseline_digest": self.baseline["checks"][rid]["digest"],
            "final_digest": digest(check), "final_status": status,
            "snapshot_fingerprint": self.baseline["snapshot_fingerprint"],
            "outcome": "confirmed",
            "attacker_perspective": "重新檢查是否存在不經物件擁有者驗證即可呼叫服務的入口",
            "search_summary": "重新閱讀所有服務呼叫點與查詢執行位置，確認額外資料存取分支",
            "hypotheses": [
                {"attack_surface": f"attack-path-{n}", "attempt":
                 f"重新檢查第 {n} 種跨身分查詢及 Controller 對 Handler 的替代路徑是否可繞過控制",
                 "result": result, "evidence": self.loc}
                for n in range(hypothesis_count)
            ],
            "contradictions": [], "open_issues": [],
        }

    def evaluate(self):
        _write(self.root / REVIEWS, self.records)
        return second_pass_errors(self.root, self.assessment)

    def test_all_70_control_results_have_second_pass_contract(self):
        self.assertEqual(len(self.rules), 70)
        for rid in self.rules:
            item = guidance(rid)
            self.assertTrue(item["single_agent"])
            self.assertFalse(item["truly_independent"])
            self.assertIn(item["required_hypotheses"], (1, 2))
        self.assertEqual(guidance("AC-08")["required_hypotheses"], 2)
        self.assertEqual(self.evaluate(), [])

    def test_second_pass_missing_or_baseline_missing_blocks_final_report(self):
        del self.records["AC-08"]
        self.assertIn("AC-08: 第二輪反向複核缺少紀錄", str(self.evaluate()))
        _write(self.root / BASELINE, {"schema_version": 1,
                                     "snapshot_fingerprint": self.baseline["snapshot_fingerprint"],
                                     "checks": {}})
        self.assertIn("第一輪結論 ID", str(self.evaluate()))
        (self.root / BASELINE).unlink()
        self.assertIn("--begin-second-pass", str(self.evaluate()))

    def test_every_high_risk_control_needs_distinct_counterexamples(self):
        record = self.records["AC-08"]
        record["hypotheses"] = record["hypotheses"][:1]
        self.assertIn("至少需要 2 個", str(self.evaluate()))
        record["hypotheses"].append(copy.deepcopy(record["hypotheses"][0]))
        self.assertIn("攻擊面缺少名稱或與其他反例重複", str(self.evaluate()))

    def test_unresolved_and_contradictory_evidence_blocks_delivery(self):
        a = self.records["AC-08"]
        a["open_issues"] = ["尚未檢查直接 SQL 呼叫"]
        self.assertIn("仍有未完成", str(self.evaluate()))
        a["open_issues"] = []
        a["hypotheses"][0]["result"] = "confirmed_vulnerability"
        self.assertIn("與正式 pass 判定矛盾", str(self.evaluate()))

    def test_bogus_source_and_comment_only_proofs_do_not_pass(self):
        a = self.records["AC-08"]
        a["hypotheses"][0]["evidence"]["line_start"] = 9999
        a["hypotheses"][0]["evidence"]["line_end"] = 9999
        self.assertIn("行號超出", str(self.evaluate()))
        a["hypotheses"][0]["evidence"] = {"kind": "source", "path": "../secret.cs",
                                           "line_start": 1, "line_end": 1}
        self.assertIn("來源路徑不存在", str(self.evaluate()))

    def test_change_of_conclusion_requires_new_digest_and_resolved_contradiction(self):
        check = self.check("AC-08")
        check["status"] = "fail"
        check["finding_ids"] = ["F-IDOR"]
        self.assessment["findings"] = [{"id": "F-IDOR", "check_ids": ["AC-08"]}]
        record = self.records["AC-08"]
        record["final_status"] = "fail"
        record["final_digest"] = digest(check)
        record["outcome"] = "corrected"
        record["hypotheses"][0]["result"] = "confirmed_vulnerability"
        self.assertIn("必須有矛盾發現", str(self.evaluate()))
        record["contradictions"] = [{
            "initial_status": "pass", "final_status": "fail",
            "resolution": "重新核對所有物件讀取路徑後找到可繞過擁有者檢查的直接查詢分支，並建立 Finding",
            "evidence": self.loc,
        }]
        self.assertEqual(self.evaluate(), [])

    def test_cannot_erase_confirmed_fail_or_finding(self):
        c = self.check("AC-08")
        c["status"] = "fail"
        c["finding_ids"] = ["F-1"]
        self.baseline["checks"]["AC-08"] = {"status": "fail", "digest": digest(c)}
        _write(self.root / BASELINE, self.baseline)
        c["status"] = "pass"
        del c["finding_ids"]
        self.records["AC-08"]["final_digest"] = digest(c)
        self.records["AC-08"]["baseline_digest"] = self.baseline["checks"]["AC-08"]["digest"]
        self.assertIn("不得在第二輪被靜默降級", str(self.evaluate()))

    def test_old_record_invalid_after_source_or_check_update(self):
        check = self.check("AC-08")
        check["decision_reason"] = "另一個新證據分支需要核對"
        self.assertIn("第二輪結論與目前正式檢核不同", str(self.evaluate()))
        check.pop("decision_reason")
        self.snapshot["source_hashes"]["NewEndpoint.cs"] = "added"
        _write(self.root / SNAPSHOT, self.snapshot)
        self.assertIn("第一輪快照與目前來源不同", str(self.evaluate()))

    def test_real_deployment_configuration_proof_is_accepted(self):
        deployment = self.root / "deployment.yaml"
        deployment.write_text("replicas: 3\n", encoding="utf-8")
        self.snapshot["source_hashes"]["deployment.yaml"] = "synthetic-deployment-sha"
        _write(self.root / SNAPSHOT, self.snapshot)
        stamp = snapshot_fingerprint(self.snapshot)
        self.baseline["snapshot_fingerprint"] = stamp
        c = self.check("BC-03")
        c["status"] = "pass"
        c["execution"]["inspected_paths"].append("deployment.yaml")
        c["evidence"] = [{"kind": "configuration", "path": "deployment.yaml",
                          "line_start": 1, "line_end": 1}]
        self.baseline["checks"]["BC-03"] = {"status": "pass", "digest": digest(c)}
        _write(self.root / BASELINE, self.baseline)
        for record in self.records.values():
            record["snapshot_fingerprint"] = stamp
        item = self.make_record(c)
        item["hypotheses"][0]["evidence"] = {
            "kind": "configuration", "path": "deployment.yaml",
            "line_start": 1, "line_end": 1
        }
        self.records["BC-03"] = item
        self.assertEqual(self.evaluate(), [])

    def test_real_external_gap_must_match_decision_audit(self):
        rid = "BC-03"
        check = self.check(rid)
        check["status"] = "review"
        check["review_kind"] = "external_only"
        self.baseline["checks"][rid] = {"status": "review", "digest": digest(check)}
        _write(self.root / BASELINE, self.baseline)
        a = self.make_record(check)
        a["hypotheses"][0]["evidence"] = {
            "kind": "external_gap", "artifact": "正式部署拓撲與切換測試"
        }
        self.records[rid] = a
        self.assertIn("外部缺口須對應", str(self.evaluate()))
        _write(self.root / Path("reports/security-code-review/analysis/decision-audits.json"),
               {rid: {"external_gap": {"artifact": "正式部署拓撲與切換測試"}}})
        self.assertEqual(self.evaluate(), [])

    def test_begin_requires_70_completed_checks_not_partial(self):
        self.check("AC-08")["execution"]["state"] = "pending"
        with self.assertRaisesRegex(ValueError, "先完成全部 70 項"):
            begin_second_pass(self.root, self.assessment)

    def test_begin_does_not_skip_unintegrated_or_source_recheck_obligations(self):
        _write(self.root / "reports/security-code-review/analysis/recheck-required.json",
               {"rule_ids": ["AC-08"]})
        with self.assertRaisesRegex(ValueError, "重新查核規則"):
            begin_second_pass(self.root, self.assessment)
        (self.root / "reports/security-code-review/analysis/recheck-required.json").unlink()
        _write(self.root / "reports/security-code-review/analysis/staged/draft.json",
               {"snapshot_git_revision": "synthetic-test-revision"})
        with self.assertRaisesRegex(ValueError, "未整合的第一輪暫存"):
            begin_second_pass(self.root, self.assessment)

    def test_begin_pins_completed_first_pass_and_is_idempotent(self):
        (self.root / BASELINE).unlink()
        with (patch("review_safety.snapshot_errors", return_value=[]),
              patch("review_safety.closure_errors", return_value=[]),
              patch("control_effectiveness.verification_errors", return_value=[]),
              patch("decision_adjudication.adjudication_errors", return_value=[]),
              patch("review_completion.completion_errors", return_value=[]),
              patch("review_decision.decision_quality_errors", return_value=[]),
              patch("source_coverage.build_source_coverage", return_value={
                  "review_integrity_errors": [], "missing_source_file_count": 0,
              })):
            first = begin_second_pass(self.root, self.assessment)
            second = begin_second_pass(self.root, self.assessment)
            self.assertEqual(first["rule_count"], 70)
            self.assertFalse(first["already_existed"])
            self.assertTrue(second["already_existed"])
            self.check("AC-08")["decision_reason"] = "correction requiring review"
            with self.assertRaisesRegex(ValueError, "禁止自動覆寫"):
                begin_second_pass(self.root, self.assessment)

    def test_explicit_restart_archives_previous_results_instead_of_erasing(self):
        old = copy.deepcopy(self.baseline)
        self.check("AC-08")["decision_reason"] = "不同的複核後來源結論"
        with (patch("review_safety.snapshot_errors", return_value=[]),
              patch("review_safety.closure_errors", return_value=[]),
              patch("control_effectiveness.verification_errors", return_value=[]),
              patch("decision_adjudication.adjudication_errors", return_value=[]),
              patch("review_completion.completion_errors", return_value=[]),
              patch("review_decision.decision_quality_errors", return_value=[]),
              patch("source_coverage.build_source_coverage", return_value={
                  "review_integrity_errors": [], "missing_source_file_count": 0,
              })):
            with self.assertRaisesRegex(ValueError, "禁止自動覆寫"):
                begin_second_pass(self.root, self.assessment)
            result = begin_second_pass(self.root, self.assessment, restart=True)
        self.assertTrue(result["restarted"])
        archive = list((self.root / "reports/security-code-review/analysis/second-pass-history")
                       .glob("*.json"))
        self.assertEqual(len(archive), 1)
        history = json.loads(archive[0].read_text("utf-8"))
        self.assertEqual(history["first_pass_baseline"], old)
        self.assertIn("AC-08", history["adversarial_reviews"])
        self.assertEqual(json.loads((self.root / REVIEWS).read_text("utf-8")), {})
        self.assertEqual(progress(self.root, self.assessment)["pending_count"], 70)

    def test_staged_second_pass_can_integrate_and_conflict_is_rejected(self):
        # 只測試 staging API；此合成 assessment 並非完整實際審查。
        _write(report_dir(self.root) / "assessment.json",
               {"checks": self.checks, "file_reviews": [], "findings": []})
        draft = report_dir(self.root) / "adversarial-draft.json"
        _write(draft, {"adversarial_reviews": {"AC-08": self.records["AC-08"]}})
        with patch("review_safety.snapshot_errors", return_value=[]):
            stage(self.root, draft)
            saved = integrate(self.root)
            self.assertEqual(saved["adversarial_reviews"], 1)
            original = json.loads((self.root / REVIEWS).read_text("utf-8"))
            self.assertEqual(original["AC-08"], self.records["AC-08"])
            edited = copy.deepcopy(self.records["AC-08"])
            edited["search_summary"] += "，再核對一條服務入口"
            _write(draft, {"adversarial_reviews": {"AC-08": edited}})
            stage(self.root, draft)
            with self.assertRaisesRegex(ValueError, "第二輪複核紀錄衝突"):
                integrate(self.root)

    def test_stage_and_integrate_reject_missing_baseline_or_stale_result(self):
        # 這只測試資料整合，未對虛構 70 項給出實際安全結論。
        draft = report_dir(self.root) / "second-pass-test.json"
        _write(draft, {"adversarial_reviews": {"AC-08": self.records["AC-08"]}})
        with patch("review_safety.snapshot_errors", return_value=[]):
            stage(self.root, draft)
            with self.assertRaisesRegex(ValueError, "assessment.json 不存在"):
                integrate(self.root)

    def test_progress_excludes_invalid_but_present_second_pass_records(self):
        self.records["AC-08"]["open_issues"] = ["尚未查驗直接 Repository 呼叫"]
        self.evaluate()
        pending = progress(self.root, self.assessment)
        self.assertEqual(pending["pending_count"], 1)
        self.assertEqual(pending["pending_ids"], ["AC-08"])
        self.assertGreater(pending["error_count"], 0)

    def test_progress_lists_unreviewed_rules_without_faking_completed(self):
        self.assertEqual(progress(self.root, self.assessment)["pending_count"], 0)
        del self.records["AC-08"]
        _write(self.root / REVIEWS, self.records)
        pending = progress(self.root, self.assessment)
        self.assertIn("AC-08", pending["pending_ids"])
        self.assertEqual(pending["pending_count"], 1)


if __name__ == "__main__":
    unittest.main()
