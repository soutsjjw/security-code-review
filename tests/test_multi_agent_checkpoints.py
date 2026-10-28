"""Multi-agent resume and authoritative integration scenarios."""
import json
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import test_multi_agent as fixtures
from multi_agent import (ANALYSIS, LEDGER, PROBE, _read, _write, plan, claim,
                         accept, accept_stdin, begin_integration, commit_integration,
                         renew_probe, resolve_main, followup, accept_followup, summary)
from multi_agent_guard import proof_line_hash
from evidence_integrity import initialize, commit, errors as integrity_errors


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        base = fixtures.MultiAgentTests("test_probe_success_multiple_workers_and_idempotent_plan")
        base.setUp()
        self.addCleanup(base.doCleanups)
        self.fixture = base
        self.root = base.root

    def seal_official(self):
        index = self.root / ANALYSIS / "structure-index.json"
        data = _read(index)
        data["evidence_integrity_version"] = 1
        _write(index, data)
        initialize(self.root, explicit=True)
        self.assertEqual(integrity_errors(self.root), [])

    def official_transaction(self):
        assessment = _read(self.root / "reports/security-code-review/assessment.json")
        assessment["main_review_note"] = "main agent reviewed the control path"
        commit(self.root, {"assessment.json": assessment}, event="verified-main-review")

    def test_atomic_claim_batch_enforces_n_and_no_partial_write(self):
        from multi_agent import claim_batch
        self.fixture.verified_probe()
        state = plan(self.root, task_tokens=2000)
        keys = list(state["tasks"])
        assigned = [{"task_id": keys[0], "agent_id": "codex-batch-001"},
                    {"task_id": keys[1], "agent_id": "codex-batch-002"}]
        snapshot = _read(self.root / LEDGER)
        with self.assertRaisesRegex(ValueError, "重複"):
            claim_batch(self.root, [assigned[0], assigned[0]])
        self.assertEqual(_read(self.root / LEDGER), snapshot)
        result = claim_batch(self.root, assigned)
        self.assertEqual(len(result["claimed"]), 2)
        self.assertEqual(summary(self.root)["task_counts"]["running"], 2)

    def test_window_renews_when_no_remaining_shard_fits(self):
        from multi_agent import renew_budget
        self.fixture.verified_probe()
        state = plan(self.root, task_tokens=2000, budget_tokens=12000)
        ids = list(state["tasks"])
        first = claim(self.root, ids[0], agent_id="codex-check-001")
        self.assertTrue(accept_stdin(
            self.root, json.dumps(self.fixture.result(first), ensure_ascii=False))["accepted"])
        with self.assertRaisesRegex(ValueError, "預算"):
            claim(self.root, ids[1], agent_id="codex-check-002")
        self.assertEqual(renew_budget(self.root)["budget_window"], 2)
        self.assertEqual(claim(self.root, ids[1], agent_id="codex-check-002")["task_id"], ids[1])

    def test_legal_main_transaction_advances_report_guard(self):
        self.seal_official()
        self.fixture.verified_probe()
        state = plan(self.root, task_tokens=2000)
        first_task = next(iter(state["tasks"]))
        self.assertTrue(begin_integration(self.root)["integration_open"])
        with self.assertRaisesRegex(ValueError, "整合窗口"):
            claim(self.root, first_task, agent_id="codex-check-001")
        with self.assertRaisesRegex(ValueError, "新的有效"):
            commit_integration(self.root)
        self.official_transaction()
        self.assertTrue(commit_integration(self.root)["integration_closed"])
        self.assertEqual(claim(self.root, first_task, agent_id="codex-check-001")["task_id"], first_task)

    def test_unauthorized_report_edit_cannot_be_whitelisted(self):
        self.seal_official()
        self.fixture.verified_probe()
        plan(self.root, task_tokens=2000)
        begin_integration(self.root)
        path = self.root / "reports/security-code-review/assessment.json"
        path.write_text('{"tampered":true}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Manifest|完整性"):
            commit_integration(self.root)

    def test_accepted_result_persists_and_rejects_replay_tampering(self):
        self.fixture.verified_probe()
        state = plan(self.root, task_tokens=2000)
        task_id = next(iter(state["tasks"]))
        task = claim(self.root, task_id, agent_id="codex-check-001")
        result = self.fixture.result(task)
        self.assertTrue(accept_stdin(self.root, json.dumps(result, ensure_ascii=False))["accepted"])
        evidence = self.root / ANALYSIS / "multi-agent/results" / (task_id + ".json")
        self.assertTrue(evidence.exists())
        self.assertEqual(_read(evidence), result)
        evidence.write_text('{"corrupted":true}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Worker 證據"):
            summary(self.root)

    def test_sensitive_worker_message_rejected_before_persistence(self):
        self.fixture.verified_probe()
        state = plan(self.root, task_tokens=2000)
        task_id = next(iter(state["tasks"]))
        task = claim(self.root, task_id, agent_id="codex-check-001")
        data = self.fixture.result(task)
        data["issues"] = ["Server=sample;Password=unsafe"]
        with self.assertRaisesRegex(ValueError, "落地"):
            accept_stdin(self.root, json.dumps(data, ensure_ascii=False))
        self.assertFalse((self.root / ANALYSIS / "multi-agent/results" / (task_id + ".json")).exists())

    def test_reprobe_preserves_accepted_work_and_rejects_running(self):
        self.fixture.verified_probe()
        state = plan(self.root, task_tokens=2000)
        ids = list(state["tasks"])
        task = claim(self.root, ids[0], agent_id="codex-check-001")
        result = self.fixture.result(task)
        self.assertTrue(accept_stdin(self.root, json.dumps(result, ensure_ascii=False))["accepted"])
        running = claim(self.root, ids[1], agent_id="codex-check-002")
        submitted = self.fixture_probe_data()
        with self.assertRaisesRegex(ValueError, "執行中的工作"):
            renew_probe(self.root, submitted)
        from multi_agent import fail
        fail(self.root, ids[1])
        before = _read(self.root / LEDGER)["tasks"][ids[0]]["result_digest"]
        renewed = renew_probe(self.root, submitted)
        self.assertTrue(renewed["renewed"])
        self.assertEqual(_read(self.root / LEDGER)["tasks"][ids[0]]["result_digest"], before)

    def fixture_probe_data(self):
        from multi_agent import probe_template
        original = probe_template()
        original.update(codex_version="codex-cli test-version",
                        trace_path=str(self.fixture.trace), execution_id="trial-2",
                        evidence_note="第二次獨立試跑驗證沙箱唯讀、上下文隔離、失敗復原和執行器識別均符合約束")
        original["checks"] = {name: True for name in original["checks"]}
        return original

    def test_main_ends_cross_shard_followup_after_formal_review(self):
        index_path = self.root / ANALYSIS / "structure-index.json"
        index = _read(index_path)
        index["cross_file_call_hints"] = {
            "src/AuthController.cs": [{
                "called_method": "ResolvePolicy", "caller_line": 1,
                "possible_targets": [{"path": "src/InputService.cs", "line": 1}]
            }]
        }
        _write(index_path, index)
        self.seal_official()
        self.fixture.verified_probe()
        state = plan(self.root, task_tokens=2000)
        task_id = next(k for k, v in state["tasks"].items()
                       if any(x["path"] == "src/AuthController.cs"
                              for x in v["task"]["assigned_paths"]))
        task = claim(self.root, task_id, agent_id="codex-check-001")
        result = self.fixture.result(task)
        target_file = next(row for row in result["files"] if row["path"] == "src/AuthController.cs")
        target_file["unresolved_symbols"] = [{
            "path": "src/AuthController.cs", "name": "ResolvePolicy", "line_start": 1,
            "reason": "待由主代理查證跨檔候選函式的實際授權流程與執行路徑"}]
        self.assertTrue(accept_stdin(self.root, json.dumps(result, ensure_ascii=False))["needs_followup"])
        follow = followup(self.root, task_id, agent_id="codex-check-002")
        proof = {
            "path": "src/InputService.cs", "line_start": 1, "line_end": 1,
            "line_hash": proof_line_hash(self.root, "src/InputService.cs", 1),
            "summary": "在跨檔呼叫候選中定位實際目標程式，仍須主代理查證"}
        followup_document = {
            "task_id": task_id, "round": follow["round"],
            "agent_instance_id": follow["agent_instance_id"],
            "snapshot_fingerprint": follow["snapshot_fingerprint"],
            "resolved": [{"path": "src/AuthController.cs", "name": "ResolvePolicy",
                          "line_start": 1, "evidence": proof}]}
        temp = self.root / ANALYSIS / "multi-agent/followup-result.json"
        temp.write_text(json.dumps(followup_document, ensure_ascii=False), encoding="utf-8")
        self.assertEqual(accept_followup(self.root, temp)["status"], "needs_main")
        begin_integration(self.root)
        self.official_transaction()
        commit_integration(self.root)
        current_manifest = _read(self.root / ANALYSIS / "integrity-manifest.json")
        resolved = {"task_id": task_id, "manifest_head": current_manifest["head"],
                    "resolved": [{
                        "path": "src/AuthController.cs", "name": "ResolvePolicy", "line_start": 1,
                        "target_path": "src/InputService.cs", "target_line": 1,
                        "target_line_hash": proof_line_hash(self.root, "src/InputService.cs", 1),
                        "reason": "主代理已逐行核對跨分片呼叫鏈、實際候選目標及安全控制的分支條件，並完成正式審查紀錄與交易日誌完整性核對"}]}
        doc_path = self.root / ANALYSIS / "multi-agent/main-resolution.json"
        doc_path.write_text(json.dumps(resolved, ensure_ascii=False), encoding="utf-8")
        self.assertEqual(resolve_main(self.root, task_id, doc_path)["status"], "completed")


if __name__ == "__main__":
    unittest.main()
