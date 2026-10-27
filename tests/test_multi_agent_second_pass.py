"""Adversarial second-pass independent executor and result-ledger regression tests."""
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import test_multi_agent as fixture_module
from multi_agent import ANALYSIS, LEDGER, accept as first_accept, claim as first_claim, plan as first_plan
from multi_agent_guard import proof_line_hash
from multi_agent_second_pass import plan, claim, accept, status, SECOND, _read


class SecondPassTests(unittest.TestCase):
    def setUp(self):
        fixture = MultiAgentTests("test_probe_success_multiple_workers_and_idempotent_plan")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.root = fixture.root
        fixture.verified_probe()
        first = first_plan(self.root, task_tokens=2000)
        for i, task_id in enumerate(first["tasks"]):
            task = first_claim(self.root, task_id, agent_id=f"codex-first-{i}")
            path = self.root / f"first-result-{i}.txt"
            path.write_text(json.dumps(fixture.result(task)), "utf-8")
            self.assertTrue(first_accept(self.root, path)["accepted"])
        report = self.root / ANALYSIS
        (report / "first-pass-baseline.json").write_text(
            json.dumps({"schema_version": 1, "snapshot_fingerprint": first["snapshot_fingerprint"],
                        "checks": {"AC-01": {"digest": "a" * 64}}}), "utf-8")
        first_path = self.root / LEDGER
        self.first = json.loads(first_path.read_text("utf-8"))
        self.work = {"ready": True, "rule_tasks": [
            {"rule_id": "AC-01",
             "evidence_anchors": [{"path": "src/AuthController.cs",
                                  "line_start": 1, "line_end": 1}],
             "candidate_paths": [], "needs_new_anchor": False,
             "status": "pass", "decision_reason": "Should never be shown"}],
            "sample_tasks": [],
            "rules_pending": 70}
        p = patch("second_pass_layers.worklist", return_value=self.work)
        p.start()
        self.addCleanup(p.stop)

    def response(self, task):
        lines = task["challenge_lines"]
        rendered = {}
        for path, line_numbers in lines.items():
            rendered[path] = [{"line": n,
                               "sha256": proof_line_hash(self.root, path, n)}
                              for n in line_numbers]
        return {"schema_version": 1, "task_id": task["task_id"],
                "agent_instance_id": task["agent_instance_id"],
                "snapshot_fingerprint": task["snapshot_fingerprint"],
                "hypothesis": {
                    "attacker_precondition": "攻擊者有一般使用者身分，可以指定不同目標物件識別碼",
                    "expected_violation": "若查詢沒有驗證擁有者，可能直接讀取其他使用者資源",
                    "inspection_steps": "重新開啟受測入口與實際查詢位置，核對授權分支和參數",
                    "observed_behavior": "已核對指定來源實際行與回傳條件，需由主代理再檢查調用鏈",
                    "evidence": {"path": "src/AuthController.cs", "line_start": 1,
                                 "line_end": 1,
                                 "line_hash": proof_line_hash(self.root,
                                                              "src/AuthController.cs", 1),
                                 "summary": "實際重讀來源第一行方法宣告，需核對調用鏈內的授權拒絕分支"}
                },
                "line_challenges": rendered, "issues": []}

    def test_plan_never_returns_first_pass_verdict(self):
        ledger = plan(self.root)
        raw = json.dumps(ledger["tasks"], ensure_ascii=False)
        self.assertNotIn("Should never be shown", raw)
        self.assertNotIn('"status": "pass"', raw)

    def test_same_executor_for_rule_is_rejected(self):
        ledger = plan(self.root)
        task_id = next(iter(ledger["tasks"]))
        with self.assertRaisesRegex(ValueError, "同一子代理"):
            claim(self.root, task_id, "codex-first-0")

    def test_new_executor_can_submit_verified_counterexample(self):
        ledger = plan(self.root)
        task_id = next(iter(ledger["tasks"]))
        task = claim(self.root, task_id, "codex-second-new")
        result_file = self.root / "second-result.txt"
        result_file.write_text(json.dumps(self.response(task), ensure_ascii=False), "utf-8")
        self.assertTrue(accept(self.root, result_file)["accepted"])
        self.assertTrue(accept(self.root, result_file)["idempotent"])
        self.assertTrue(status(self.root)["all_challenges_received"])
        self.assertFalse(status(self.root)["official_second_pass_completed"])

    def test_tampered_challenge_and_report_write_fail_closed(self):
        ledger = plan(self.root)
        task_id = next(iter(ledger["tasks"]))
        task = claim(self.root, task_id, "codex-second-new")
        result = self.response(task)
        key = next(iter(result["line_challenges"]))
        result["line_challenges"][key][0]["sha256"] = "0" * 64
        output = self.root / "wrong-challenge.txt"
        output.write_text(json.dumps(result), "utf-8")
        with self.assertRaisesRegex(ValueError, "SHA256"):
            accept(self.root, output)
        (self.root / ANALYSIS / "adversarial-reviews.json").write_text("{}", "utf-8")
        with self.assertRaisesRegex(ValueError, "異動"):
            status(self.root)


if __name__ == "__main__":
    unittest.main()
