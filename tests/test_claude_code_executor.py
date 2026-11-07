"""Claude Code 執行器：版本綁定、只核可第一輪、子代理紀錄驗收與唯讀 Worker 定義。"""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/lib"))

import multi_agent_guard as guard
import multi_agent_workers as workers
from multi_agent_ledger import PROBE
from multi_agent_planning import probe_template, record_probe
from review_core import load_json_object

CC_VERSION = "2.1.317 (Claude Code)"


class RuntimeBindingTests(unittest.TestCase):
    def test_requires_claude_code_process(self):
        with patch.dict(os.environ, {"CLAUDECODE": ""}, clear=False):
            self.assertIsNone(guard.runtime_binding("claude-code"))

    def test_prefers_running_executable_version_over_path_cli(self):
        env = {"CLAUDECODE": "1",
               "CLAUDE_CODE_EXECPATH": r"C:\Data\claude-code\2.1.317\a33aa\claude.exe"}
        with patch.dict(os.environ, env, clear=False), \
                patch("multi_agent_guard.subprocess.run") as run:
            self.assertEqual(guard.runtime_binding("claude-code"), CC_VERSION)
            run.assert_not_called()

    def test_falls_back_to_cli_and_rejects_unknown_executor(self):
        env = {"CLAUDECODE": "1", "CLAUDE_CODE_EXECPATH": ""}
        with patch.dict(os.environ, env, clear=False), \
                patch("multi_agent_guard.subprocess.run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = "2.1.318 (Claude Code)\n"
            self.assertEqual(guard.runtime_binding("claude-code"), "2.1.318 (Claude Code)")
            self.assertEqual(run.call_args[0][0], ["claude", "--version"])
        self.assertIsNone(guard.runtime_binding("other"))


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.trace = self.root / "trace.jsonl"
        self.trace.write_text('{"type":"assistant"}\n', encoding="utf-8")

    def cc_probe(self, **overrides):
        item = probe_template("claude-code")
        item.update(executor_version=CC_VERSION, execution_id="cc-trial-1",
                    trace_path=str(self.trace),
                    evidence_note="同一則訊息平行啟動兩個 security-review-worker，寫入因工具不存在被拒，惡意註解未被遵從。")
        item["checks"] = {k: True for k in item["checks"]}
        item.update(overrides)
        return item

    def test_templates_keep_codex_unchanged_and_drop_isolation_for_claude_code(self):
        codex = probe_template()
        self.assertIn("codex_version", codex)
        self.assertNotIn("executor", codex)
        self.assertEqual(set(codex["checks"]), set(guard.CHECKS))
        cc = probe_template("claude-code")
        self.assertEqual(cc["executor"], "claude-code")
        self.assertNotIn("first_pass_result_isolation", cc["checks"])
        self.assertEqual(len(cc["checks"]), len(guard.CHECKS) - 1)
        with self.assertRaises(ValueError):
            probe_template("other")

    def test_record_and_verify_claude_code_probe(self):
        with patch("multi_agent_planning.runtime_binding", return_value=CC_VERSION), \
                patch("multi_agent_guard.runtime_binding", return_value=CC_VERSION):
            self.assertTrue(record_probe(self.root, self.cc_probe())["verified"])
            stored = load_json_object(self.root / PROBE)
            self.assertEqual(stored["executor"], "claude-code")
            self.assertEqual(guard.probe_errors(self.root, stored), [])
        with patch("multi_agent_guard.runtime_binding", return_value="2.1.318 (Claude Code)"):
            self.assertIn("執行器版本不符或無法核實", guard.probe_errors(self.root, stored))
        self.assertTrue(guard.second_pass_executor_errors(stored))
        self.assertEqual(guard.second_pass_executor_errors({"codex_version": "x"}), [])

    def test_claude_code_probe_rejects_codex_check_set_and_version_mismatch(self):
        bad_checks = self.cc_probe()
        bad_checks["checks"]["first_pass_result_isolation"] = True
        with patch("multi_agent_planning.runtime_binding", return_value=CC_VERSION):
            with self.assertRaises(ValueError):
                record_probe(self.root, bad_checks)
            with self.assertRaises(ValueError):
                record_probe(self.root, self.cc_probe(executor_version="2.1.318 (Claude Code)"))

    def test_probe_errors_rejects_extra_or_missing_checks(self):
        probe = {"verified": True, "executor": "claude-code", "executor_version": CC_VERSION,
                 "checks": {k: True for k in guard.CHECKS}, "verified_at": time.time(),
                 "trace_path": str(self.trace),
                 "trace_sha256": guard.sha(self.trace.read_bytes())}
        with patch("multi_agent_guard.runtime_binding", return_value=CC_VERSION):
            self.assertIn("能力試跑條件不完整", guard.probe_errors(self.root, probe))
            probe["checks"].pop("first_pass_result_isolation")
            self.assertEqual(guard.probe_errors(self.root, probe), [])


class TranscriptAcceptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        home = patch.object(Path, "home", return_value=self.home)
        home.start()
        self.addCleanup(home.stop)
        self.sub = self.home / ".claude/projects/proj/session/subagents"
        self.sub.mkdir(parents=True)

    def write(self, name, rows):
        path = self.sub / name
        path.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows), encoding="utf-8")
        return path

    @staticmethod
    def assistant(msg_id, *texts):
        return {"type": "assistant", "message": {"id": msg_id, "content": [
            {"type": "text", "text": t} for t in texts]}}

    def test_extracts_final_message_and_strips_fence(self):
        path = self.write("agent-a.jsonl", [
            self.assistant("m1", "reading files"),
            {"type": "assistant", "message": {"id": "m2", "content": [
                {"type": "tool_use", "name": "Read", "input": {}}]}},
            self.assistant("m3", "```json\n{\"task_id\":", "\"x\"}\n```")])
        self.assertEqual(workers.transcript_final_text(path), '{"task_id":"x"}')

    def test_rejects_paths_outside_subagent_transcripts(self):
        outside = self.home / "agent.jsonl"
        outside.write_text("{}", encoding="utf-8")
        with self.assertRaises(ValueError):
            workers.transcript_final_text(outside)
        wrong_dir = self.home / ".claude/projects/proj/session.jsonl"
        wrong_dir.write_text("{}", encoding="utf-8")
        with self.assertRaises(ValueError):
            workers.transcript_final_text(wrong_dir)
        with self.assertRaises(ValueError):
            workers.transcript_final_text(self.write("agent-b.jsonl", [
                {"type": "user", "message": {"content": "hi"}}]))

    def test_accept_transcript_uses_stdin_validation(self):
        path = self.write("agent-c.jsonl", [self.assistant("m1", '{"task_id":"y"}')])
        with patch("multi_agent_workers.accept_stdin", return_value={"accepted": True}) as accept:
            self.assertEqual(workers.accept_transcript(self.home, path), {"accepted": True})
        accept.assert_called_once_with(self.home, '{"task_id":"y"}')


class WorkerDefinitionTests(unittest.TestCase):
    def test_worker_definition_is_read_only(self):
        text = (ROOT / "agents/security-review-worker.md").read_text(encoding="utf-8")
        front = text.split("---")[1]
        tools_line = next(line for line in front.splitlines() if line.startswith("tools:"))
        tools = {t.strip() for t in tools_line.split(":", 1)[1].split(",")}
        self.assertEqual(tools, {"Read", "Grep", "Glob", "mcp__codegraph__codegraph_explore"})
        self.assertIn("name: security-review-worker", front)

    def test_docs_describe_claude_code_first_pass_only(self):
        guide = (ROOT / "docs/multi-agent-review.md").read_text(encoding="utf-8")
        self.assertIn("## Claude Code 子代理調度（僅第一輪）", guide)
        self.assertIn("--accept-transcript", guide)
        self.assertIn("--categories", guide)
        skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("multi-agent-review.md#claude-code-子代理調度僅第一輪", skill)


if __name__ == "__main__":
    unittest.main()
