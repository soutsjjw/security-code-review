"""Claude Code 對話紀錄 Token 統計：去重、階段歸屬、子代理與 CodeGraph 警告。"""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/lib"))

from transcript_usage import (classify_tool_use, main, project_dir_name,
                              summarize_directory, summarize_session)


def _usage(read=1000, write=10, inp=5, out=50):
    return {"input_tokens": inp, "cache_read_input_tokens": read,
            "cache_creation_input_tokens": write, "output_tokens": out}


def _assistant(msg_id, blocks, usage):
    return {"type": "assistant", "message": {"id": msg_id, "content": blocks, "usage": usage}}


def _bash(command):
    return {"type": "tool_use", "name": "Bash", "input": {"command": command}}


def _skill_prompt(args=""):
    return {"type": "user", "message": {"content": (
        "<command-name>/anthropic-skills:security-code-review</command-name>"
        f"<command-args>{args}</command-args>")}}


def _write(path: Path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n", encoding="utf-8")


class TranscriptUsageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_project_dir_name_replaces_every_non_alphanumeric(self):
        name = project_dir_name(Path("C:/Users/a/repos/Clean.Arch/Clean.Arch"))
        self.assertTrue(name.endswith("Users-a-repos-Clean-Arch-Clean-Arch"))
        self.assertNotRegex(name, r"[^A-Za-z0-9-]")

    def test_split_message_lines_count_once_with_final_usage(self):
        rows = [_skill_prompt(),
                _assistant("m1", [{"type": "text", "text": "x"}], _usage(out=3)),
                _assistant("m1", [_bash("cat -n src/A.cs")], _usage(out=80)),
                _assistant("m2", [_bash("python scripts/review_queue.py --compact")], _usage(read=3000))]
        _write(self.dir / "s1.jsonl", rows)
        result = summarize_session(self.dir / "s1.jsonl")
        self.assertEqual(result["totals"]["api_calls"], 2)
        self.assertEqual(result["totals"]["cache_read_input_tokens"], 4000)
        self.assertEqual(result["totals"]["output_tokens"], 130)
        self.assertEqual(result["phases"]["source_read"]["api_calls"], 1)
        self.assertEqual(result["phases"]["skill:review_queue"]["cache_read_input_tokens"], 3000)
        self.assertEqual(result["max_context_tokens"], 3015)

    def test_classification(self):
        self.assertEqual(classify_tool_use(_bash("python scripts/review_safety.py --plan"))[0],
                         "skill:review_safety")
        self.assertEqual(classify_tool_use(_bash("cat > ev.json <<'EOF'\n{}\nEOF")),
                         ("authoring", False))
        self.assertEqual(classify_tool_use({"type": "tool_use", "name": "Read", "input": {}})[0],
                         "source_read")
        self.assertEqual(classify_tool_use(_bash("codegraph explore \"Login\"")), ("codegraph", True))
        self.assertEqual(classify_tool_use(
            {"type": "tool_use", "name": "mcp__codegraph__codegraph_explore", "input": {}}),
            ("codegraph", True))
        self.assertEqual(classify_tool_use({"type": "tool_use", "name": "Agent", "input": {}})[0],
                         "subagent_dispatch")
        self.assertEqual(classify_tool_use(_bash("ls -la .codegraph")), ("shell_other", False))

    def test_warns_when_codegraph_available_but_never_queried(self):
        probe = {"type": "user", "message": {"content": [{"type": "tool_result", "content":
                 '{"codegraph": {"available": true, "command": "codegraph explore <query>"}}'}]}}
        _write(self.dir / "s2.jsonl", [_skill_prompt(), probe,
                                         _assistant("m1", [_bash("ls .codegraph")], _usage())])
        result = summarize_session(self.dir / "s2.jsonl")
        self.assertTrue(result["codegraph_available"])
        self.assertEqual(result["warnings"], ["codegraph_available_but_unused"])

    def test_codegraph_available_detected_in_key_value_output(self):
        probe = {"type": "user", "message": {"content": [{"type": "tool_result", "content":
                 'roslyn={"available": false} codegraph={"available":true,"command":"codegraph explore"}'}]}}
        _write(self.dir / "s4.jsonl", [_skill_prompt(), probe,
                                         _assistant("m1", [_bash("ls")], _usage())])
        result = summarize_session(self.dir / "s4.jsonl")
        self.assertTrue(result["codegraph_available"])
        self.assertEqual(result["warnings"], ["codegraph_available_but_unused"])

    def test_codegraph_unavailable_or_unrelated_key_does_not_warn(self):
        probe = {"type": "user", "message": {"content": [{"type": "tool_result", "content":
                 'codegraph={"available":false} my_codegraph={"available":true}'}]}}
        _write(self.dir / "s5.jsonl", [_skill_prompt(), probe,
                                         _assistant("m1", [_bash("ls")], _usage())])
        result = summarize_session(self.dir / "s5.jsonl")
        self.assertFalse(result["codegraph_available"])
        self.assertEqual(result["warnings"], [])

    def test_multi_agent_without_subagent_transcripts_warns_and_with_them_counts(self):
        rows = [_skill_prompt("--multi-agent --agents 3"),
                _assistant("m1", [_bash("python scripts/multi_agent.py --plan")], _usage())]
        _write(self.dir / "s3.jsonl", rows)
        self.assertIn("multi_agent_without_subagents",
                      summarize_session(self.dir / "s3.jsonl")["warnings"])
        _write(self.dir / "s3" / "subagents" / "agent-1.jsonl",
               [_assistant("w1", [_bash("codegraph explore Foo")], _usage(read=500))])
        result = summarize_session(self.dir / "s3.jsonl")
        self.assertEqual(result["subagent_transcripts"], 1)
        self.assertEqual(result["subagent_totals"]["cache_read_input_tokens"], 500)
        self.assertEqual(result["codegraph_calls"], 1)
        self.assertEqual(result["warnings"], [])

    def _run_log(self):
        def event(ts, name, phase, outcome="ok"):
            return {"timestamp": ts, "run_id": "20261108-000000-abcd1234", "event": name,
                    "phase": phase, "outcome": outcome}
        rows = [event("2026-11-08T10:00:00+08:00", "run_started", "initialization"),
                event("2026-11-08T11:00:00+08:00", "stage", "first_pass"),
                event("2026-11-08T11:05:00+08:00", "begin-second-pass", "second_pass"),
                event("2026-11-08T13:00:00+08:00", "integrate", "second_pass"),
                event("2026-11-08T13:10:00+08:00", "run_finished", "report", "completed")]
        logs = self.dir / "logs"
        _write(logs / "20261108-000000-abcd1234.jsonl", rows)
        (logs / "latest.json").write_text(json.dumps({"run_id": "20261108-000000-abcd1234"}), "utf-8")
        return logs

    def test_run_log_splits_usage_by_review_phase_and_reports_waits(self):
        from transcript_usage import load_run_windows
        logs = self._run_log()
        windows = load_run_windows(logs / "latest.json")

        def at(msg_id, utc, read):
            row = _assistant(msg_id, [_bash("cat a.cs")], _usage(read=read))
            row["timestamp"] = utc
            return row
        _write(self.dir / "t" / "s6.jsonl", [
            _skill_prompt(),
            at("m0", "2026-11-08T01:59:00Z", 1),     # 執行開始前
            at("m1", "2026-11-08T02:58:00Z", 100),   # 第一輪，前面等了 59 分
            at("m2", "2026-11-08T03:06:00Z", 20),    # 第二輪
            at("m3", "2026-11-08T04:56:00Z", 30),    # 第二輪，前面等了 110 分
            at("m4", "2026-11-08T05:05:00Z", 5),     # 最後一批整合後到結束
            at("m5", "2026-11-08T06:00:00Z", 2)])    # 執行結束後
        result = summarize_session(self.dir / "t" / "s6.jsonl", windows)
        phases = result["review_phases"]
        self.assertEqual(list(phases), ["before_run", "setup_and_first_pass", "second_pass",
                                        "finalize", "after_run"])
        self.assertEqual(phases["setup_and_first_pass"]["cache_read_input_tokens"], 100)
        self.assertEqual(phases["second_pass"]["api_calls"], 2)
        self.assertEqual(phases["second_pass"]["wait_seconds"], 110 * 60)
        self.assertEqual(phases["setup_and_first_pass"]["wait_seconds"], 59 * 60)
        self.assertEqual(phases["finalize"]["wait_seconds"], 0)
        self.assertEqual(result["run_log"]["run_id"], "20261108-000000-abcd1234")

    def test_cli_run_log_keeps_only_sessions_overlapping_the_run(self):
        logs = self._run_log()
        inside = _assistant("m1", [], _usage())
        inside["timestamp"] = "2026-11-08T02:30:00Z"
        outside = _assistant("m1", [], _usage())
        outside["timestamp"] = "2026-11-07T02:30:00Z"
        _write(self.dir / "t" / "in.jsonl", [_skill_prompt(), inside])
        _write(self.dir / "t" / "out.jsonl", [_skill_prompt(), outside])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(["--transcripts", str(self.dir / "t"),
                                   "--run-log", str(logs / "latest.json")]), 0)
        text = out.getvalue()
        self.assertIn("review phases (run 20261108-000000-abcd1234)", text)
        self.assertIn("setup_and_first_pass", text)
        self.assertTrue(text.startswith("in "))
        self.assertNotIn("out ", text)

    def test_run_log_without_second_pass_is_all_first_pass(self):
        from transcript_usage import load_run_windows, review_phase_for
        _write(self.dir / "r.jsonl", [
            {"timestamp": "2026-11-08T10:00:00+08:00", "event": "run_started", "phase": "initialization"},
            {"timestamp": "2026-11-08T12:00:00+08:00", "event": "stage", "phase": "first_pass"}])
        windows = load_run_windows(self.dir / "r.jsonl")
        from datetime import datetime, timezone
        self.assertEqual(review_phase_for(datetime(2026, 11, 8, 3, tzinfo=timezone.utc), windows),
                         "setup_and_first_pass")
        self.assertEqual(review_phase_for(datetime(2026, 11, 8, 5, tzinfo=timezone.utc), windows),
                         "after_run")

    def test_run_log_rejects_summary_without_run_id(self):
        from transcript_usage import load_run_windows
        (self.dir / "latest.json").write_text('{"run_id": "../x"}', "utf-8")
        with self.assertRaises(ValueError):
            load_run_windows(self.dir / "latest.json")

    def test_directory_skips_sessions_without_skill_unless_all(self):
        _write(self.dir / "a.jsonl", [_skill_prompt(), _assistant("m", [], _usage())])
        _write(self.dir / "b.jsonl", [_assistant("m", [], _usage())])
        self.assertEqual([r["session_id"] for r in summarize_directory(self.dir)], ["a"])
        self.assertEqual(len(summarize_directory(self.dir, include_all=True)), 2)

    def test_cli_json_output_contains_no_transcript_text(self):
        _write(self.dir / "c.jsonl", [_skill_prompt(), _assistant(
            "m", [_bash("grep -n SECRET_VALUE src/A.cs")], _usage())])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(["--transcripts", str(self.dir), "--json"]), 0)
        self.assertNotIn("SECRET_VALUE", out.getvalue())
        self.assertEqual(json.loads(out.getvalue())[0]["phases"]["source_read"]["api_calls"], 1)


if __name__ == "__main__":
    unittest.main()
