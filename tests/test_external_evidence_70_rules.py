"""P0-P3 70-rule external responsibility/evidence gate regression.

Synthetic contracts test validators, not vulnerability detection or audit quality.
"""
from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from control_effectiveness import REQUIRED_SCENARIOS, _external_pass_errors, snapshot_fingerprint
from cross_file_evidence import trace_errors
from decision_adjudication import adjudication_errors
from review_blockers import summarize
from review_decision import load_decision_matrix


class AllRuleExternalEvidenceTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        (self.root / "Control.cs").write_text(
            "services.AddAuthentication().AddExternalProvider();\n",
            encoding="utf-8",
        )
        self.snapshot = {
            "git_revision": "contract-test-revision",
            "source_hashes": {"Control.cs": "example-fixed-source-hash"},
        }
        self.loc = {"kind": "source", "path": "Control.cs",
                    "line_start": 1, "line_end": 1}
        self.matrix = load_decision_matrix()
        self.assertEqual(len(self.matrix), 70)

    def inputs(self, rid):
        mode = self.matrix[rid]["mode"]
        kind = ("external_only" if mode == "external"
                else "external_responsibility_pending")
        artifact = f"已核對之 {rid} 部署控制責任交付紀錄"
        check = {
            "id": rid, "status": "review", "review_kind": kind,
            "decision_reason": "已核對儲存庫內可取得的責任範圍；待確認：" + artifact,
            "execution": {"state": "completed", "inspected_paths": ["Control.cs"]},
            "evidence": [
                {**self.loc, "description": "已閱讀外部控制註冊與責任轉接設定"},
                {"kind": "deployment", "artifact_id": "verified-delegation",
                 "description": "外部平台責任交付的真實識別碼（合成測試）"},
            ],
        }
        audit = {
            "status": "review", "review_kind": kind,
            "git_revision": self.snapshot["git_revision"],
            "snapshot_fingerprint": snapshot_fingerprint(self.snapshot),
            "static_result": ("external_control" if mode == "external"
                              else "delegated_control"),
            "static_conclusion": "已檢閱應用程式目前可確認的控制責任與部署邊界，未冒稱外部平台控制已生效",
            "searched_paths": ["Control.cs"], "static_evidence": [],
            "responsibility_evidence": {"kind": "deployment",
                                        "artifact_id": "verified-delegation"},
            "responsibility_reason": "根據實際責任移交紀錄，此外部平台負責本規則控制實施與執行結果",
            "repository_search_summary": "已確認儲存庫內的來源、設定與可用控制路徑，沒有將外部責任當作本地執行",
            "external_gap": {
                "category": "deployment",
                "artifact": artifact,
                "evidence_owner": "正式系統部署與維運負責單位",
                "blocking_question": "正式部署環境的實際控制結果是否符合本條安全條件",
                "why_decisive": "儲存庫可核對外部責任歸屬，但沒有實際環境運作成果，不足以確認該控制安全有效",
                "manual_boundary": self.matrix[rid]["manual_boundary"],
                "decision_outcomes": {
                    "if_satisfied": {
                        "status": "pass",
                        "reason": "如外部平台的真實執行結果證實全部適用安全條件與防繞過要求均成立，則符合",
                    },
                    "if_unsatisfied": {
                        "status": "fail",
                        "reason": "如外部平台的執行結果確認必要控制失效或遭繞過，則須產生實際弱點紀錄",
                    },
                },
            },
            "open_static_questions": [],
        }
        return check, audit

    def evaluate(self, check, audit):
        return adjudication_errors(
            self.root, [check],
            index_override={"decision_adjudication_version": 1,
                            "decision_quality_version": 1},
            snapshot_override=self.snapshot,
            audits_override={check["id"]: audit},
        )

    def test_all_70_review_modes_accept_only_applicable_external_contract(self):
        counts = {"hybrid": 0, "static": 0, "external": 0}
        for rid, rule in self.matrix.items():
            with self.subTest(rule=rid):
                counts[rule["mode"]] += 1
                check, audit = self.inputs(rid)
                self.assertEqual(self.evaluate(check, audit), [])
                bad = copy.deepcopy(audit)
                if rule["mode"] == "external":
                    bad["static_result"] = "delegated_control"
                else:
                    bad["responsibility_evidence"]["artifact_id"] = "fabricated"
                self.assertTrue(self.evaluate(check, bad))
        self.assertEqual(counts, {"static": 29, "hybrid": 24, "external": 17})

    def test_every_static_and_hybrid_requires_real_ownership_and_scope(self):
        for rid, rule in self.matrix.items():
            if rule["mode"] == "external":
                continue
            with self.subTest(rule=rid):
                check, audit = self.inputs(rid)
                for field in ("responsibility_evidence", "repository_search_summary"):
                    broken = copy.deepcopy(audit)
                    broken.pop(field)
                    self.assertTrue(self.evaluate(check, broken), field)
                broken = copy.deepcopy(audit)
                broken["searched_paths"] = []
                self.assertTrue(self.evaluate(check, broken))
                broken = copy.deepcopy(audit)
                broken["static_result"] = "control_satisfied"
                self.assertTrue(self.evaluate(check, broken))
                broken = copy.deepcopy(check)
                broken["review_kind"] = "external_only"
                self.assertTrue(self.evaluate(broken, audit))

    def test_all_53_nonexternal_rules_require_true_effectiveness_for_external_pass(self):
        for rid, info in self.matrix.items():
            if info["mode"] == "external":
                continue
            with self.subTest(rule=rid):
                check, audit = self.inputs(rid)
                check["status"] = "pass"
                check.pop("review_kind")
                proof = {"kind": "deployment", "artifact_id": "verified-delegation"}
                record = {
                    "status": "pass", "control_proof_mode": "external_verified",
                    "git_revision": self.snapshot["git_revision"],
                    "snapshot_fingerprint": snapshot_fingerprint(self.snapshot),
                    "responsibility_evidence": proof,
                    "control_evidence": proof,
                    "responsibility_reason": audit["responsibility_reason"],
                    "repository_search_summary": audit["repository_search_summary"],
                    "control_condition": "正式部署控制需依規則安全條件執行並對每個受保護操作生效",
                    "failure_behavior": "不符合條件的操作必須由正式控制拒絕並保留必要紀錄",
                    "search_summary": "已核對部署平台控制及相關的完整必要攻擊／繞過情境與真實工件",
                    "bypass_scenarios": [
                        {"scenario": name, "outcome": "blocked",
                         "reason": "使用已取得的正式控制驗證紀錄核對此攻擊情境並確認控制拒絕",
                         "evidence": proof}
                        for name in REQUIRED_SCENARIOS.get(rid, ("alternate_or_bypass_path",))
                    ],
                    "open_issues": [],
                }
                required = set(REQUIRED_SCENARIOS.get(rid, ("alternate_or_bypass_path",)))
                self.assertEqual(_external_pass_errors(
                    self.root, check, record, {"Control.cs"}, self.snapshot, required), [])
                broken = copy.deepcopy(record)
                broken.pop("control_evidence")
                self.assertTrue(_external_pass_errors(
                    self.root, check, broken, {"Control.cs"}, self.snapshot, required))
                broken = copy.deepcopy(record)
                broken["bypass_scenarios"] = []
                self.assertTrue(_external_pass_errors(
                    self.root, check, broken, {"Control.cs"}, self.snapshot, required))

    def test_delegated_cross_file_review_does_not_fabricate_control_trace(self):
        check, audit = self.inputs("SI-01")
        target = self.root / "reports/security-code-review/analysis"
        target.mkdir(parents=True)
        (target / "decision-audits.json").write_text(
            json.dumps({"SI-01": audit}, ensure_ascii=False), encoding="utf-8")
        self.assertEqual(trace_errors(
            self.root, {"cross_file_evidence_version": 1}, self.snapshot,
            check, {}, "cross_file"), [])
        bad = copy.deepcopy(audit)
        bad["responsibility_evidence"]["artifact_id"] = "unverified"
        (target / "decision-audits.json").write_text(
            json.dumps({"SI-01": bad}, ensure_ascii=False), encoding="utf-8")
        self.assertTrue(trace_errors(
            self.root, {"cross_file_evidence_version": 1}, self.snapshot,
            check, {}, "cross_file"))

    def test_blocker_fingerprint_is_stable_and_rule_scoped(self):
        errs = ["IN-05: 控制位置與正式證據不一致",
                "DP-01: 來源證據只含宣告，不能證明控制有效",
                "SI-01: P0 外部控制責任缺少真實證據"]
        first = summarize(errs)
        self.assertEqual(first["recheck_rule_ids"], ["DP-01", "IN-05", "SI-01"])
        self.assertEqual(first["blocker_signature"], summarize(list(reversed(errs)))["blocker_signature"])
        self.assertFalse(first["ready_for_second_pass"])
        self.assertTrue(summarize([])["ready_for_second_pass"])
        self.assertNotEqual(first["blocker_signature"], summarize(errs[:-1])["blocker_signature"])


if __name__ == "__main__":
    unittest.main()
