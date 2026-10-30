"""誤判的已確認 fail 只能經授權、反證與完整紀錄撤回，Finding 全文不得消失。"""
from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/lib"))

import evidence_integrity as ledger
from adversarial_recheck import digest, second_pass_errors
from analysis_prepare import prepare
from flow_acceptance import preservation
from review_core import snapshot_fingerprint
from review_queue import initialize, load_rules
from review_safety import _write, integrate, stage

FINDING = {
    "id": "F-001", "title": "疑似缺少資源擁有者驗證", "severity": "high",
    "confidence": "confirmed", "check_ids": ["AC-08"],
    "evidence": [{"kind": "source", "description": "端點直接以 id 取資料",
                  "collected_on": "2026-10-30", "source_version": "test",
                  "path": "Handler.cs", "line_start": 1, "line_end": 1}],
    "impact": "可能越權存取他人資料", "remediation": "加入擁有者驗證",
}
WITHDRAWAL = {
    "reason": "重新追查呼叫鏈後確認 Handler 只由 OwnerGuard 包裝後呼叫，擁有者比對在進入資料存取前已強制執行，原判定的越權路徑不存在。",
    "first_pass_error": "第一輪只讀到 Handler.cs，沒有追到 Guard.cs 的包裝層與 DI 註冊。",
    "reviewer": "security-review-agent",
    "counter_evidence": [{"path": "Guard.cs", "line_start": 2, "line_end": 2,
                          "description": "OwnerGuard 在呼叫 Handler 前比對資源擁有者，不符即拒絕"}],
}


class FailWithdrawalTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.report = self.root / "reports/security-code-review"
        (self.root / "Example.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
            '<TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>',
            encoding="utf-8")
        (self.root / "Handler.cs").write_text(
            "public Item Get(int id) => _db.Find(id);\n", encoding="utf-8")
        (self.root / "Guard.cs").write_text(
            "public class OwnerGuard {\n"
            "  public Item Get(int id) => Owns(id) ? _handler.Get(id) : throw new Forbidden();\n"
            "}\n", encoding="utf-8")
        with patch("analysis_prepare.probe_roslyn", return_value={"available": False}), \
             patch("analysis_prepare.probe_codegraph", return_value={"available": False}):
            prepare(self.root)
        ruleset, rules = load_rules()
        initialize(self.root, self.report, ruleset, rules)
        assessment = self.assessment()
        self.failed = self._check(assessment, "AC-08")
        self.failed.update(status="fail", finding_ids=["F-001"],
                           decision_reason="Handler 直接以 id 取資料，未見擁有者驗證")
        self.failed.setdefault("execution", {})["state"] = "completed"
        assessment["findings"] = [FINDING]
        ledger.commit(self.root, {"assessment.json": assessment}, event="test-seeded-fail")
        self.assertEqual(ledger.errors(self.root), [])

    def assessment(self) -> dict:
        return json.loads((self.report / "assessment.json").read_text("utf-8"))

    @staticmethod
    def _check(assessment: dict, rid: str) -> dict:
        return next(c for c in assessment["checks"] if c["id"] == rid)

    def corrected(self, status: str = "pass") -> dict:
        record = copy.deepcopy(self.failed)
        record.update(status=status, finding_ids=[],
                      decision_reason="OwnerGuard 在資料存取前強制比對擁有者，原越權路徑不存在")
        return record

    def stage_payload(self, payload: dict) -> None:
        draft = self.report / "withdrawal.json"
        _write(draft, payload)
        stage(self.root, draft)

    def test_downgrade_without_withdrawal_flag_is_rejected(self):
        self.stage_payload({"checks": [self.corrected()], "fail_withdrawals": {"AC-08": WITHDRAWAL}})
        with self.assertRaisesRegex(ValueError, "--allow-fail-withdrawal"):
            integrate(self.root, allow_revision=True)
        with self.assertRaisesRegex(ValueError, "--allow-revision"):
            integrate(self.root, allow_fail_withdrawal=True)
        self.assertEqual(self.assessment()["findings"], [FINDING])
        self.assertEqual(ledger.errors(self.root), [])

    def test_flag_without_withdrawal_record_is_rejected(self):
        self.stage_payload({"checks": [self.corrected()]})
        with self.assertRaisesRegex(ValueError, "fail_withdrawals"):
            integrate(self.root, allow_revision=True, allow_fail_withdrawal=True)
        self.assertEqual(self.assessment()["findings"], [FINDING])

    def test_counter_evidence_must_point_at_real_source_lines(self):
        bad = copy.deepcopy(WITHDRAWAL)
        bad["counter_evidence"][0]["line_end"] = 99
        self.stage_payload({"checks": [self.corrected()], "fail_withdrawals": {"AC-08": bad}})
        with self.assertRaisesRegex(ValueError, "行號超出"):
            integrate(self.root, allow_revision=True, allow_fail_withdrawal=True)
        missing = dict(WITHDRAWAL, counter_evidence=[])
        for path in (self.report / "analysis/staged").glob("*.json"):
            path.unlink()
        self.stage_payload({"checks": [self.corrected()], "fail_withdrawals": {"AC-08": missing}})
        with self.assertRaisesRegex(ValueError, "反證"):
            integrate(self.root, allow_revision=True, allow_fail_withdrawal=True)
        self.assertEqual(self.assessment()["findings"], [FINDING])

    def test_withdrawal_keeps_full_finding_and_passes_schema(self):
        self.stage_payload({"checks": [self.corrected("review")],
                            "fail_withdrawals": {"AC-08": WITHDRAWAL}})
        integrate(self.root, allow_revision=True, allow_fail_withdrawal=True)
        current = self.assessment()
        self.assertEqual(current["findings"], [])
        self.assertEqual(self._check(current, "AC-08")["status"], "review")
        [record] = current["fail_withdrawals"]
        self.assertEqual(record["rule_id"], "AC-08")
        self.assertEqual((record["previous_status"], record["new_status"]), ("fail", "review"))
        self.assertEqual(record["withdrawn_findings"], [FINDING])
        self.assertEqual(record["finding_ids"], ["F-001"])
        self.assertEqual(record["counter_evidence"], WITHDRAWAL["counter_evidence"])
        self.assertEqual(len(record["finding_sha256"]["F-001"]), 64)
        schema = json.loads((ROOT / "schemas/assessment.schema.json").read_text("utf-8"))
        jsonschema.validate({"fail_withdrawals": current["fail_withdrawals"]},
                            {**schema, "required": []})
        self.assertEqual(ledger.errors(self.root), [])
        before = {"findings": [FINDING]}
        self.assertEqual(preservation(before, current), ([], []))
        self.assertEqual(preservation(before, {"findings": []}), (["F-001"], []))

    def test_finding_shared_with_remaining_fail_rule_cannot_be_withdrawn(self):
        assessment = self.assessment()
        other = self._check(assessment, "AC-07")
        other.update(status="fail", finding_ids=["F-001"])
        other.setdefault("execution", {})["state"] = "completed"
        assessment["findings"][0]["check_ids"] = ["AC-07", "AC-08"]
        ledger.commit(self.root, {"assessment.json": assessment}, event="test-shared-finding")
        self.failed = self._check(assessment, "AC-08")
        self.stage_payload({"checks": [self.corrected()], "fail_withdrawals": {"AC-08": WITHDRAWAL}})
        with self.assertRaisesRegex(ValueError, "仍關聯未撤回的規則 AC-07"):
            integrate(self.root, allow_revision=True, allow_fail_withdrawal=True)
        self.assertEqual(len(self.assessment()["findings"]), 1)

    def test_withdrawal_for_rule_that_stays_fail_is_rejected(self):
        self.stage_payload({"fail_withdrawals": {"AC-08": WITHDRAWAL}})
        with self.assertRaisesRegex(ValueError, "只能用於本批由已完成 fail 改判"):
            integrate(self.root, allow_revision=True, allow_fail_withdrawal=True)

    def test_second_pass_accepts_only_recorded_withdrawal(self):
        assessment = self.assessment()
        for check in assessment["checks"]:
            check.setdefault("execution", {})["state"] = "completed"
        snapshot = json.loads((self.report / "analysis/review-snapshot.json").read_text("utf-8"))
        baseline = {"schema_version": 1, "snapshot_fingerprint": snapshot_fingerprint(snapshot),
                    "checks": {c["id"]: {"status": c["status"], "digest": digest(c)}
                               for c in assessment["checks"]}}
        corrected = self._check(assessment, "AC-08")
        corrected.update(status="pass", finding_ids=[])
        reviews = {"AC-08": {"outcome": "corrected", "final_status": "pass",
                             "baseline_digest": baseline["checks"]["AC-08"]["digest"],
                             "final_digest": digest(corrected)}}
        downgrade = "AC-08: 已確認弱點不得在第二輪被靜默降級"
        errors = second_pass_errors(self.root, assessment, baseline_override=baseline,
                                    snapshot_override=snapshot, reviews_override=reviews)
        self.assertTrue(any(e.startswith(downgrade) for e in errors))
        assessment["fail_withdrawals"] = [{"rule_id": "AC-08", "new_status": "pass"}]
        errors = second_pass_errors(self.root, assessment, baseline_override=baseline,
                                    snapshot_override=snapshot, reviews_override=reviews)
        self.assertFalse(any(e.startswith(downgrade) for e in errors))

    def test_cli_requires_allow_revision(self):
        run = subprocess.run([sys.executable, str(ROOT / "scripts/review_safety.py"),
                              "--target", str(self.root), "--integrate", "--allow-fail-withdrawal"],
                             capture_output=True, text=True, encoding="utf-8",
                             env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        self.assertEqual(run.returncode, 2)
        self.assertIn("--allow-revision", run.stderr)


if __name__ == "__main__":
    unittest.main()
