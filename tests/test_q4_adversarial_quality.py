"""Q4 第二輪品質測試：具體攻擊、真正重新閱讀、模板與漏判修訂。"""
from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/lib"))

from adversarial_quality import quality_errors
from control_effectiveness import snapshot_fingerprint
from quality_baseline import load_catalog, PROJECT_FILE
from review_safety import _write
from review_snapshot import report_dir


class AdversarialQualityTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        case = next(x for x in load_catalog()["cases"] if x["id"] == "idor-owner-checked")
        (self.root / "Case.csproj").write_text(PROJECT_FILE, encoding="utf-8")
        for name, source in case["files"].items():
            (self.root / name).write_text(source, encoding="utf-8")
        self.snapshot = {
            "schema_version": 1, "git_revision": "fixture-revision",
            "source_hashes": {path: f"verified-hash-{path}" for path in case["files"]},
        }
        _write(report_dir(self.root) / "analysis/review-snapshot.json", self.snapshot)
        self.first_claim = (
            "本案例由 Service 將目前登入使用者 ID 帶入 Repository 查詢條件，"
            "避免直接用物件 ID 取回他人資料"
        )
        self.entry = self.loc("OrderController.cs", "_handler.Handle(id, principal)")
        self.guard = self.loc("OrderService.cs", "_repository.FindByOwner(id, userId)")
        self.operation = self.loc("OrderRepository.cs", "FindByOwner(int id")
        self.check = {
            "id": "AC-08", "status": "pass",
            "decision_reason": self.first_claim,
            "evidence": [{"kind": "source", **self.guard}],
            "execution": {"state": "completed",
                          "inspected_paths": ["OrderController.cs", "OrderHandler.cs",
                                              "OrderService.cs", "OrderRepository.cs"]},
        }
        self.baseline = {
            "snapshot_fingerprint": snapshot_fingerprint(self.snapshot),
            "checks": {"AC-08": {"status": "pass",
                                 "decision_reason": self.first_claim}},
        }
        self.record = {
            "outcome": "confirmed",
            "reassessment": {
                "first_pass_claim": self.first_claim,
                "challenge_question": "在變更物件編號及改走直接查詢入口後，是否仍由擁有者識別值限制所有讀取",
                "reinspection_summary": "重新閱讀 Controller 傳入主體、Service 擁有者查核與 Repository 查詢限制",
                "conclusion_basis": "Service 實際呼叫依擁有者限制的查詢，兩種不同路徑均有可追溯的來源拒絕條件",
                "verification_evidence": {"kind": "source", **self.guard},
            },
            "hypotheses": [
                {
                    "attack_surface": "direct_controller_order_lookup",
                    "vector": "alternate_entry",
                    "attacker_precondition": "攻擊者可自行指定不屬於自身的訂單編號並直接呼叫公開查詢入口",
                    "expected_violation": "若 Controller 未帶入登入主體，服務可能只依訂單編號返回他人資料",
                    "inspection_steps": "重新閱讀 Controller 呼叫 Handler 的參數，以及 Service 是否採用登入身分過濾",
                    "observed_behavior": "實際入口傳入登入主體，Service 從主體取得使用者 ID 並限制擁有者查詢",
                    "result": "blocked",
                    "evidence": {"kind": "source", **self.entry},
                    "inspection_evidence": {"kind": "source", **self.guard},
                },
                {
                    "attack_surface": "repository_lookup_without_owner",
                    "vector": "direct_storage_access",
                    "attacker_precondition": "攻擊者若可讓另一個服務直接呼叫 Repository 的未限制物件查詢分支",
                    "expected_violation": "繞過受保護服務的 owner 條件後將可能取得其他使用者的私人訂單",
                    "inspection_steps": "重新追查 Repository 查詢呼叫點與 Service 真正選取的 FindByOwner 方法",
                    "observed_behavior": "本案例中 Service 只呼叫含 owner 比對的 Repository 查詢方法，未見未保護分支",
                    "result": "blocked",
                    "evidence": {"kind": "source", **self.operation},
                    "inspection_evidence": {"kind": "source", **self.guard},
                },
            ],
            "contradictions": [],
            "open_issues": [],
        }
        self.assessment = {"checks": [self.check], "findings": []}

    def loc(self, name, phrase):
        lines = (self.root / name).read_text("utf-8").splitlines()
        pos = next(i for i, line in enumerate(lines, 1) if phrase in line)
        return {"path": name, "line_start": pos, "line_end": pos}

    def errors(self, *, record=None, assessment=None, baseline=None, audits=None):
        doc = assessment if assessment is not None else self.assessment
        items = {self.check["id"]: self.record if record is None else record}
        return quality_errors(self.root, doc, items,
                              self.baseline if baseline is None else baseline,
                              audits or {})

    def test_two_real_different_high_risk_hypotheses_are_accepted(self):
        self.assertEqual(self.errors(), [])

    def test_layered_challenge_uses_facts_before_first_pass_verdict(self):
        candidate = copy.deepcopy(self.record)
        candidate["reassessment"].pop("first_pass_claim")
        candidate["blind_challenge"] = {
            "factual_claim": "服務會從目前登入的使用者主體取得識別值，並將它交給資料查詢方法執行。",
            "challenge_question": "如果繞過標準控制器並直接呼叫服務，是否仍會套用相同的擁有者限制。",
            "initial_observation": "重新閱讀 Service 的實際分支，查詢執行位置明確帶入登入者識別值限制。",
            "evidence": {"kind": "source", **self.guard},
        }
        records = {"AC-08": candidate, "__layered__": {"plan": {"version": 1}}}
        self.assertEqual(quality_errors(self.root, self.assessment, records,
                                        self.baseline, {}), [])
        candidate["blind_challenge"].pop("initial_observation")
        self.assertIn("blind_challenge.initial_observation",
                      str(quality_errors(self.root, self.assessment, records,
                                         self.baseline, {})))

    def test_generic_surface_or_duplicate_vector_is_rejected(self):
        candidate = copy.deepcopy(self.record)
        candidate["hypotheses"][0]["attack_surface"] = "AC-08-adversarial-surface-1"
        candidate["hypotheses"][1]["vector"] = "alternate_entry"
        errors = self.errors(record=candidate)
        self.assertIn("制式 attack_surface", "；".join(errors))
        self.assertIn("至少兩種不同攻擊向量", "；".join(errors))

    def test_attack_precondition_and_actual_reinspection_cannot_be_empty(self):
        candidate = copy.deepcopy(self.record)
        candidate["hypotheses"][0].pop("attacker_precondition")
        candidate["hypotheses"][1]["inspection_evidence"] = {
            "kind": "source", "path": "../outside.cs", "line_start": 1, "line_end": 1
        }
        errors = self.errors(record=candidate)
        self.assertIn("attacker_precondition", "；".join(errors))
        self.assertIn("來源路徑不存在", "；".join(errors))

    def test_first_pass_claim_must_be_fixed_in_immutable_baseline(self):
        candidate = copy.deepcopy(self.record)
        candidate["reassessment"]["first_pass_claim"] = "完全不同的第一輪結論"
        self.assertIn("未引用第一輪固定", "；".join(self.errors(record=candidate)))
        baseline = copy.deepcopy(self.baseline)
        baseline["checks"]["AC-08"].pop("decision_reason")
        self.assertIn("錨點缺少原始判定理由",
                      "；".join(self.errors(baseline=baseline)))

    def test_unrelated_attack_pairs_cannot_fake_independent_hypotheses(self):
        candidate = copy.deepcopy(self.record)
        candidate["hypotheses"][1]["attacker_precondition"] = (
            candidate["hypotheses"][0]["attacker_precondition"])
        candidate["hypotheses"][1]["expected_violation"] = (
            candidate["hypotheses"][0]["expected_violation"])
        self.assertIn("攻擊前提及破壞目標相同", "；".join(self.errors(record=candidate)))

    def test_all_evidence_same_line_needs_specific_explanation(self):
        candidate = copy.deepcopy(self.record)
        for row in candidate["hypotheses"]:
            row["evidence"] = {"kind": "source", **self.guard}
        errors = self.errors(record=candidate)
        self.assertIn("同一行", "；".join(errors))
        self.assertIn("控制交會點", "；".join(errors))
        candidate["shared_evidence_justification"] = (
            "兩個不同入口都會匯入 OrderService 的 FindByOwner 控制行；核對不同的呼叫前提")
        for row in candidate["hypotheses"]:
            row["same_line_explanation"] = (
                "同一條服務控制分支為兩個不同呼叫來源的共同檢查點，已分開核對攻擊前提")
        self.assertEqual(self.errors(record=candidate), [])

    def test_correction_requires_missed_reason_and_a_finding_link(self):
        check = copy.deepcopy(self.check)
        check["status"] = "fail"
        check["finding_ids"] = ["F-AC08"]
        finding = {"id": "F-AC08", "check_ids": ["AC-08"],
                   "evidence": [self.guard]}
        record = copy.deepcopy(self.record)
        record["outcome"] = "corrected"
        record["hypotheses"][0]["result"] = "confirmed_vulnerability"
        record["hypotheses"][0]["evidence"] = {"kind": "source", **self.guard}
        record["hypotheses"][0]["same_line_explanation"] = (
            "重新檢視同一條授權執行分支，這是從兩個不同入口檢查的控制責任交會點")
        record["contradictions"] = [{
            "initial_status": "pass", "final_status": "fail",
            "resolution": "第二輪找到未限制擁有者的分支，因此將原 Pass 修正為 Fail 並補充 Finding",
            "evidence": {"kind": "source", **self.guard},
        }]
        assessment = {"checks": [check], "findings": [finding]}
        errs = self.errors(record=record, assessment=assessment)
        self.assertIn("原先漏判成因", "；".join(errs))
        record["contradictions"][0]["why_first_pass_missed"] = (
            "第一輪只查核原先預期的查詢服務，未檢視可跳過限制的資料存取替代路徑")
        record["contradictions"][0]["corrective_action"] = (
            "補充失效的直接呼叫來源、修改正式判定並保留與弱點相關的完整來源證據")
        self.assertEqual(self.errors(record=record, assessment=assessment), [])
        assessment["findings"][0]["evidence"] = [self.entry]
        self.assertIn("反例未連到本規則 Finding",
                      "；".join(self.errors(record=record, assessment=assessment)))

    def test_genuine_external_only_recheck_does_not_invent_code(self):
        record = copy.deepcopy(self.record)
        proof = {"kind": "external_gap", "artifact": "正式部署拓撲與切換測試紀錄"}
        record["reassessment"]["verification_evidence"] = proof
        record["reassessment"]["first_pass_claim"] = (
            "無法由原始碼單獨判斷生產部署環境的可用性及切換控制是否真正啟用")
        record["hypotheses"] = [{
            "attack_surface": "production_failover_without_active_route",
            "vector": "operational_override",
            "attacker_precondition": "正式環境若只部署單一可用區或未啟動容錯切換，故障時無服務節點接管",
            "expected_violation": "網路節點中斷後系統不能在規定的服務恢復時間內完成自動切換",
            "inspection_steps": "核對版本控制中的部署設定，要求正式部署拓撲與演練結果工件證實切換",
            "observed_behavior": "原始碼不足以決定正式部署是否完成容錯與故障切換，需要外部拓撲紀錄",
            "result": "external_boundary",
            "evidence": proof,
            "inspection_evidence": proof,
        }]
        reason = record["reassessment"]["first_pass_claim"]
        record["reassessment"]["challenge_question"] = (
            "若未執行正式切換演練，是否能仍宣稱服務符合可用性與備援要求")
        record["reassessment"]["reinspection_summary"] = (
            "反向核對目前程式及部署設定並尋找是否有正式環境可用性證據")
        record["reassessment"]["conclusion_basis"] = (
            "此項需要實際生產拓撲和演練工件；原始碼查核不能直接證明運行部署狀態")
        assessment = {"checks": [{"id": "BC-03", "status": "review",
                                  "review_kind": "external_only",
                                  "execution": {"state": "completed", "inspected_paths": []},
                                  "evidence": []}],
                      "findings": []}
        baseline = {"snapshot_fingerprint": self.baseline["snapshot_fingerprint"],
                    "checks": {"BC-03": {"status": "review",
                                         "decision_reason": reason}}}
        self.assertEqual(quality_errors(self.root, assessment, {"BC-03": record},
                                        baseline, {"BC-03": {
                                            "external_gap": {"artifact": proof["artifact"]}
                                        }}), [])

    def test_repeated_templates_across_rules_are_detected(self):
        checks, records, originals = [], {}, {}
        for num in range(1, 7):
            rid = f"AC-{num:02d}"
            check = copy.deepcopy(self.check)
            check["id"] = rid
            check["decision_reason"] = self.first_claim.replace("物件", f"物件{num}")
            checks.append(check)
            original = {"status": "pass", "decision_reason": check["decision_reason"]}
            originals[rid] = original
            record = copy.deepcopy(self.record)
            record["reassessment"]["first_pass_claim"] = check["decision_reason"]
            records[rid] = record
        errs = quality_errors(self.root, {"checks": checks, "findings": []}, records, {
            "snapshot_fingerprint": self.baseline["snapshot_fingerprint"], "checks": originals
        }, {})
        self.assertIn("共用制式", "；".join(errs))

    def test_new_index_rejects_existing_synthetic_pass_through_old_gate(self):
        from adversarial_recheck import INDEX, second_pass_errors
        from test_adversarial_recheck import AdversarialSecondPassTests
        legacy = AdversarialSecondPassTests()
        legacy.setUp()
        try:
            self.assertEqual(second_pass_errors(legacy.root, legacy.assessment), [])
            index_path = legacy.root / INDEX
            index = json.loads(index_path.read_text(encoding="utf-8"))
            index["adversarial_quality_version"] = 1
            _write(index_path, index)
            issues = second_pass_errors(legacy.root, legacy.assessment)
            self.assertTrue(any("Q4" in issue for issue in issues), issues[:5])
        finally:
            legacy.doCleanups()

    def test_eight_rules_reusing_one_source_without_specific_reason_are_detected(self):
        checks, records, originals = [], {}, {}
        ids = ["AC-01", "AC-02", "AC-04", "AC-06", "AC-08",
               "IN-01", "IN-02", "IN-03"]
        for rid in ids:
            check = copy.deepcopy(self.check)
            check["id"] = rid
            checks.append(check)
            originals[rid] = {"status": "pass", "decision_reason": self.first_claim}
            records[rid] = copy.deepcopy(self.record)
        errs = quality_errors(self.root, {"checks": checks, "findings": []},
                              records, {"snapshot_fingerprint":
                                        self.baseline["snapshot_fingerprint"],
                                        "checks": originals}, {})
        self.assertIn("共用來源", "；".join(errs))


if __name__ == "__main__":
    unittest.main()
