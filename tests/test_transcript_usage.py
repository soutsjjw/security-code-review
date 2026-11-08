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
