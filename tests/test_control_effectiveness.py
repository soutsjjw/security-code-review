"""P2 有效性驗證契約：不讓缺乏控制鏈／反向路徑證據的 pass 結案。"""
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
                                   guidance, verification_errors)
from quality_baseline import PROJECT_FILE, load_catalog
from review_queue import load_rules, initialize
from review_safety import _write, integrate, report_dir, stage


class ControlEffectivenessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        case = next(c for c in load_catalog()["cases"] if c["id"] == "idor-owner-checked")
        (self.root / "Case.csproj").write_text(PROJECT_FILE, encoding="utf-8")
        for path, contents in case["files"].items():
            dest = self.root / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(contents, encoding="utf-8")
        with (patch("analysis_prepare.probe_roslyn", return_value={"available": False}),
              patch("analysis_prepare.probe_codegraph", return_value={"available": False})):
            prepare(self.root, "full")
        self.snapshot = json.loads(
            (self.root / "reports/security-code-review/analysis/review-snapshot.json")
            .read_text(encoding="utf-8"))
        self.check = {
            "id": "AC-08", "status": "pass",
            "execution": {"state": "completed", "methods": ["source_review"],
                          "summary": "已核對跨檔 Controller 到 Repository 的授權鏈",
                          "inspected_paths": case["required_paths"]},
            "decision_reason": "依使用者 ID 對資料庫每筆 Order 執行 owner 限制，未找到繞過的存取路徑",
        }
        self.check["evidence"] = [{**self.location(
            "OrderService.cs", "_repository.FindByOwner(id, userId)"), "kind": "source"}]
        self.record = self.good_record()

    def location(self, filename, needle):
        lines = (self.root / filename).read_text(encoding="utf-8").splitlines()
        line = next(i for i, text in enumerate(lines, 1) if needle in text)
        return {"path": filename, "line_start": line, "line_end": line}

    def good_record(self):
        entry = self.location("OrderController.cs", "GetOrder(")
        enforcement = self.location("OrderService.cs", "_repository.FindByOwner(id, userId)")
        operation = self.location("OrderRepository.cs", "FindByOwner(int id")
        scenarios = []
        for scenario in REQUIRED_SCENARIOS["AC-08"]:
            scenarios.append({
                "scenario": scenario,
                "outcome": "not_applicable" if scenario == "vertical_access" else "blocked",
                "reason": f"已逐檔核對此案例中 {scenario} 的入口、資源查詢和使用者擁有者條件，沒有其他旁路",
                "evidence": [entry, enforcement, operation],
            })
        return {
            "status": "pass",
            "git_revision": self.snapshot["git_revision"],
            "source_hashes": self.snapshot["source_hashes"],
            "entry_points": [entry],
            "enforcement_points": [enforcement],
            "protected_operations": [operation],
            "control_condition": "必須先取得登入主體的使用者識別值，再以該值做伺服端資料查詢條件",
            "failure_behavior": "找不到使用者識別值或資料擁有者不符時，查詢不回傳訂單資料",
            "search_summary": "搜尋 Controller、Handler、Service、Repository 及所有對 FindById 的呼叫位置",
            "bypass_scenarios": scenarios,
            "open_issues": [],
        }

    def evaluate(self, record=None, status="pass", state="completed"):
        check = copy.deepcopy(self.check)
        check["status"] = status
        check["execution"]["state"] = state
        if record is None:
            (self.root / VERIFICATIONS).unlink(missing_ok=True)
        else:
            _write(self.root / VERIFICATIONS, {"AC-08": record})
        return verification_errors(self.root, [check])

    def test_all_70_rules_have_explicit_mode_aware_guidance(self):
        _, rules = load_rules()
        for rule in rules:
            with self.subTest(rule=rule["id"]):
                info = guidance(rule["id"])
                self.assertEqual(info["pass_condition"] != "", True)
                self.assertTrue(info["required_scenarios"])
                self.assertIn("entry_points", info["evidence_contract"])
        self.assertIn("horizontal_access", guidance("AC-08")["required_scenarios"])
        self.assertFalse(guidance("BC-03")["required_for_pass"])

    def test_missing_p2_evidence_blocks_pass_not_fail_or_external_review(self):
        self.assertIn("P2 缺少", str(self.evaluate()))
        self.assertEqual(self.evaluate(status="fail"), [])
        self.assertEqual(self.evaluate(status="review"), [])
        self.assertEqual(self.evaluate(status="na"), [])
        self.assertEqual(self.evaluate(state="pending"), [])

    def test_real_safe_p0_chain_accepts_complete_source_grounded_record(self):
        self.assertEqual(self.evaluate(copy.deepcopy(self.record)), [])

    def test_weak_control_presence_alone_cannot_pass(self):
        bad = copy.deepcopy(self.record)
        bad["enforcement_points"] = [self.location("OrderController.cs", "public Order? GetOrder")]
        self.assertTrue(any("未與正式來源證據連結" in e for e in self.evaluate(bad)))
        bad = copy.deepcopy(self.record)
        bad["protected_operations"] = []
        self.assertTrue(any("至少需要一筆" in e for e in self.evaluate(bad)))

    def test_bypass_routes_must_all_be_checked_and_closed(self):
        bad = copy.deepcopy(self.record)
        bad["bypass_scenarios"] = bad["bypass_scenarios"][:1]
        self.assertIn("尚未核對的必要繞過情境", str(self.evaluate(bad)))
        bad = copy.deepcopy(self.record)
        bad["bypass_scenarios"][0]["outcome"] = "unresolved"
        self.assertIn("不可 pass", str(self.evaluate(bad)))
        bad = copy.deepcopy(self.record)
        bad["open_issues"] = ["存在第二個無法解析的繞過路徑"]
        self.assertIn("有未解決", str(self.evaluate(bad)))

    def test_missing_real_source_line_version_and_inspected_path_block_pass(self):
        bad = copy.deepcopy(self.record)
        bad["entry_points"][0]["line_start"] = 9999
        bad["entry_points"][0]["line_end"] = 9999
        self.assertIn("行號超出", str(self.evaluate(bad)))
        bad = copy.deepcopy(self.record)
        bad["source_hashes"]["OrderService.cs"] = "stale"
        self.assertIn("SHA256", str(self.evaluate(bad)))
        bad = copy.deepcopy(self.record)
        bad["git_revision"] = "wrong"
        self.assertIn("Git Revision", str(self.evaluate(bad)))
        bad = copy.deepcopy(self.record)
        bad["enforcement_points"][0]["path"] = "../outside.cs"
        self.assertIn("路徑不存在", str(self.evaluate(bad)))

    def test_insecure_p0_code_cannot_be_excused_as_pending_bypass_in_pass(self):
        # P0 的不安全案例已有已知弱點；待查狀態不得成為 completed pass。
        bad = copy.deepcopy(self.record)
        bad["bypass_scenarios"][0]["outcome"] = "unresolved"
        self.assertTrue(self.evaluate(bad))
        self.assertEqual(self.evaluate(None, status="fail"), [])

    def test_staged_records_are_preserved_and_conflicts_rejected(self):
        ruleset, rules = load_rules()
        initialize(self.root, report_dir(self.root), ruleset, rules)
        payload = report_dir(self.root) / "p2-draft.json"
        _write(payload, {"control_verifications": {"AC-08": self.record}})
        stage(self.root, payload)
        first = integrate(self.root)
        self.assertEqual(first["control_verifications"], 1)
        stored = json.loads((self.root / VERIFICATIONS).read_text(encoding="utf-8"))
        self.assertEqual(stored["AC-08"], self.record)
        update = copy.deepcopy(self.record)
        update["search_summary"] += " 重新確認額外服務入口"
        _write(payload, {"control_verifications": {"AC-08": update}})
        stage(self.root, payload)
        with self.assertRaisesRegex(ValueError, "P2 控制有效性紀錄衝突"):
            integrate(self.root)


if __name__ == "__main__":
    unittest.main()
