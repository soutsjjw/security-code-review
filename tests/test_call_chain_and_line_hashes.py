"""呼叫鏈預查、補查 brief、規則彙整，以及 Claude Code Worker 行原文換算雜湊。"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/lib"))

import multi_agent_ledger
import multi_agent_workers as workers
import worker_brief
from multi_agent_guard import sha

SOURCE = ["using System;", "    var user = Load(id);  ", 'string password = "hunter2xyz";', "return user;"]


def _hash(text):
    return sha(text.encode("utf-8"))


class LineHashTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "src").mkdir()
        (self.root / "src/A.cs").write_text("\n".join(SOURCE) + "\n", encoding="utf-8")

    def proof(self, line, value):
        return {"path": "src/A.cs", "line_start": line, "line_end": line, "summary": "x" * 20,
                "line_hash": value}

    def test_quoted_lines_become_real_hashes(self):
        payload = {"files": [{
            "path": "src/A.cs",
            "line_challenges": [{"line": 2, "sha256": "var user = Load(id);"},
                                {"line": 3, "sha256": "SENSITIVE_LINE"}],
            "rule_states": [{"rule_id": "AC-01", "evidence": [self.proof(4, "return user;")]}],
            "findings": [{"path": "src/A.cs", "line_start": 2, "line_hash": "  var user = Load(id);",
                          "evidence": [self.proof(1, "using System;")]}]}],
            "resolved": [{"evidence": self.proof(4, "return user;")}]}
        out = workers.materialize_line_hashes(self.root, payload)
        entry = out["files"][0]
        self.assertEqual(entry["line_challenges"][0]["sha256"], _hash(SOURCE[1]))
        self.assertEqual(entry["line_challenges"][1]["sha256"], _hash(SOURCE[2]))
        self.assertEqual(entry["rule_states"][0]["evidence"][0]["line_hash"], _hash(SOURCE[3]))
        self.assertEqual(entry["findings"][0]["line_hash"], _hash(SOURCE[1]))
        self.assertEqual(entry["findings"][0]["evidence"][0]["line_hash"], _hash(SOURCE[0]))
        self.assertEqual(out["resolved"][0]["evidence"]["line_hash"], _hash(SOURCE[3]))

    def test_mismatches_and_unsafe_paths_are_rejected(self):
        cases = [
            self.proof(2, "var user = Load(other);"),
            self.proof(2, "SENSITIVE_LINE"),
            self.proof(99, "return user;"),
            {**self.proof(1, "using System;"), "path": "../outside.cs"},
        ]
        for proof in cases:
            with self.subTest(proof=proof):
                workers.materialize_line_hashes(self.root, {"resolved": [{"evidence": proof}]})
                self.assertEqual(proof["line_hash"], workers.LINE_TEXT_MISMATCH)
        untouched = self.proof(1, "a" * 64)
        workers.materialize_line_hashes(self.root, {"resolved": [{"evidence": untouched}]})
        self.assertEqual(untouched["line_hash"], "a" * 64)

    def test_quoting_a_secret_line_is_refused(self):
        with self.assertRaises(ValueError):
            workers.materialize_line_hashes(self.root, {"resolved": [{"evidence": self.proof(3, SOURCE[2])}]})


class AcceptTranscriptRoutingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name) / "home"
        self.root = Path(self.tmp.name) / "target"
        (self.root / "src").mkdir(parents=True)
        (self.root / "src/A.cs").write_text("\n".join(SOURCE) + "\n", encoding="utf-8")
        home = patch.object(Path, "home", return_value=self.home)
        home.start()
        self.addCleanup(home.stop)
        self.sub = self.home / ".claude/projects/p/s/subagents"
        self.sub.mkdir(parents=True)

    def transcript(self, payload):
        path = self.sub / "agent-x.jsonl"
        path.write_text(json.dumps({"type": "assistant", "message": {"id": "m", "content": [
            {"type": "text", "text": json.dumps(payload, ensure_ascii=False)}]}}), encoding="utf-8")
        return path

    def set_probe(self, executor):
        probe = self.root / multi_agent_ledger.PROBE
        probe.parent.mkdir(parents=True, exist_ok=True)
        probe.write_text(json.dumps({"executor": executor} if executor else {"codex_version": "x"}),
                         encoding="utf-8")

    def test_claude_code_converts_and_routes_followups(self):
        self.set_probe("claude-code")
        payload = {"task_id": "t", "round": 1, "resolved": [{"evidence": {
            "path": "src/A.cs", "line_start": 4, "line_hash": "return user;"}}]}
        with patch("multi_agent_workers.accept_followup_stdin", return_value={"ok": 1}) as followup, \
                patch("multi_agent_workers.accept_stdin") as first:
            self.assertEqual(workers.accept_transcript(self.root, self.transcript(payload)), {"ok": 1})
        first.assert_not_called()
        sent = json.loads(followup.call_args[0][1])
        self.assertEqual(sent["resolved"][0]["evidence"]["line_hash"], _hash(SOURCE[3]))

    def test_codex_probe_leaves_payload_untouched(self):
        self.set_probe(None)
        payload = {"task_id": "t", "files": [{"path": "src/A.cs", "line_challenges": [
            {"line": 4, "sha256": "return user;"}]}]}
        with patch("multi_agent_workers.accept_stdin", return_value={"accepted": False}) as first:
            workers.accept_transcript(self.root, self.transcript(payload))
        self.assertEqual(json.loads(first.call_args[0][1])["files"][0]["line_challenges"][0]["sha256"],
                         "return user;")


def _task(paths, consult=()):
    return {"task_id": "a" * 20, "snapshot_fingerprint": "b" * 64,
            "assigned_paths": [{"path": p, "candidate_rule_ids": ids} for p, ids in paths],
            "consult_paths": list(consult)}


class CallChainTests(unittest.TestCase):
    INDEX = {"cross_file_call_hints": {
        "src/Login.cs": [
            {"called_method": "SignIn", "caller_line": 3,
             "possible_targets": [{"path": "src/Auth.cs", "line": 9}, {"path": "src/Other.cs", "line": 1}]},
            {"called_method": "SignIn", "caller_line": 8, "possible_targets": []},
            {"called_method": "Log", "caller_line": 5, "possible_targets": [{"path": "src/Auth.cs", "line": 2}]}]}}

    def test_query_terms_prefer_called_methods_then_file_stems(self):
        task = _task([("src/Login.cs", ["AU-01"]), ("src/Account.cs", ["AC-01", "AC-02"])])
        self.assertEqual(worker_brief.query_terms(task, self.INDEX), ["SignIn", "Log"])
        self.assertEqual(worker_brief.query_terms(task, {}), ["Account", "Login"])

    def test_roslyn_hints_only_list_readable_targets(self):
        lines = worker_brief.roslyn_hint_lines(_task([("src/Login.cs", [])], ["src/Auth.cs"]), self.INDEX)
        self.assertEqual(len(lines), 2)
        self.assertTrue(all("src/Other.cs" not in line for line in lines))

    def test_codegraph_output_drops_source_and_secrets(self):
        output = ("**Relationships**\n- Login → Auth\n\n**Source Code**\n```csharp\n1\tclass Login {}\n```\n")
        run = SimpleNamespace(returncode=0, stdout=output)
        with patch("worker_brief.shutil.which", return_value="codegraph"), \
                patch("worker_brief.probe_codegraph", return_value={"available": True}), \
                patch("worker_brief.subprocess.run", return_value=run) as called:
            text = worker_brief.codegraph_relations(Path("."), ["Login"])
        self.assertIn("Login → Auth", text)
        self.assertNotIn("class Login", text)
        self.assertIn("explore", called.call_args[0][0])
        leaked = SimpleNamespace(returncode=0, stdout='**Relationships**\napi_key = "abcdef123"\n')
        with patch("worker_brief.shutil.which", return_value="codegraph"), \
                patch("worker_brief.probe_codegraph", return_value={"available": True}), \
                patch("worker_brief.subprocess.run", return_value=leaked):
            self.assertIsNone(worker_brief.codegraph_relations(Path("."), ["Login"]))
        with patch("worker_brief.probe_codegraph", return_value={"available": False}):
            self.assertIsNone(worker_brief.codegraph_relations(Path("."), ["Login"]))

    def test_section_is_capped_and_has_fallback(self):
        with patch("worker_brief.codegraph_relations", return_value="x\n" * 9000):
            text = worker_brief.call_chain_section(Path("."), _task([("src/Login.cs", [])]), {})
        self.assertLessEqual(len(text), worker_brief.CALL_CHAIN_LIMIT + 60)
        self.assertIn("已截斷", text)
        with patch("worker_brief.codegraph_relations", return_value=None):
            text = worker_brief.call_chain_section(Path("."), _task([("src/Login.cs", [])]), {})
        self.assertIn("沒有可用的 CodeGraph 結果", text)


class BriefVariantsTests(unittest.TestCase):
    def test_claude_code_brief_explains_quoted_lines(self):
        task = {**_task([("src/Login.cs", ["AU-01"])]), "schema_version": 1, "worker_id": "worker-0"}
        self.assertIn("行雜湊填法", worker_brief.build_brief(task, "## 預查", "claude-code"))
        self.assertNotIn("行雜湊填法", worker_brief.build_brief(task, None, "codex"))

    def test_followup_brief_written_for_followup_running_task(self):
        symbols = [{"name": "SignIn", "path": "src/Login.cs", "line_start": 3, "reason": "x" * 12}]
        row = {"status": "followup_running", "followup_round": 1, "followup_agent": "cc-aaaaaaaa-1",
               "unresolved_symbols": symbols, "task": _task([("src/Login.cs", [])], ["src/Auth.cs"])}
        state = {"snapshot_fingerprint": "b" * 64, "tasks": {"a" * 20: row}}
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(multi_agent_ledger, "active_plan", return_value=(state, {})), \
                patch("worker_brief.codegraph_relations", return_value=None):
            result = worker_brief.write_brief(Path(tmp), "a" * 20)
            text = Path(result["brief_path"]).read_text(encoding="utf-8")
        self.assertEqual(result["kind"], "followup")
        self.assertTrue(result["brief_path"].endswith("-followup-1.md"))
        self.assertIn('"unresolved_symbols":[{"name":"SignIn"', text)
        self.assertIn('"round":1', text)
        self.assertNotIn("十類 70 項適用性索引", text)


class RuleSummaryTests(unittest.TestCase):
    def test_summarizes_accepted_results_by_rule(self):
        result = {"files": [
            {"path": "src/A.cs", "rule_states": [
                {"rule_id": "AC-03", "status": "hit", "reason": "r" * 300,
                 "evidence": [{"path": "src/A.cs", "line_start": 2, "line_end": 4, "line_hash": "h" * 64}]},
                {"rule_id": "BC-01", "status": "not_applicable", "reason": "n" * 20, "evidence": []}],
             "findings": [{"rule_id": "AC-03", "path": "src/A.cs", "line_start": 2, "line_end": 4,
                           "sink": "Redirect"}]},
            {"path": "src/B.cs", "rule_states": [
                {"rule_id": "AC-03", "status": "unassessed", "reason": "u" * 20, "evidence": []}],
             "findings": []}]}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "r.json").write_text(json.dumps(result), encoding="utf-8")
            state = {"tasks": {"t1": {"result_digest": "d", "result_path": "r.json"},
                               "t2": {"result_digest": None}}}
            with patch.object(multi_agent_ledger, "active_plan", return_value=(state, {})):
                summary = workers.rule_evidence_summary(root)
                only = workers.rule_evidence_summary(root, ["BC-01"])
                with self.assertRaises(ValueError):
                    workers.rule_evidence_summary(root, ["ZZ-01"])
        self.assertEqual(summary["accepted_results"], 1)
        ac03 = next(r for r in summary["rules"] if r["rule_id"] == "AC-03")
        self.assertEqual((ac03["scope"], ac03["hit_count"], ac03["unassessed_paths"]),
                         ("project", 1, ["src/B.cs"]))
        self.assertEqual(len(ac03["hits"][0]["reason"]), 200)
        self.assertNotIn("line_hash", ac03["hits"][0]["evidence"][0])
        self.assertEqual(ac03["findings"][0]["sink"], "Redirect")
        self.assertIn("AU-01", summary["rules_without_worker_state"])
        self.assertEqual([r["rule_id"] for r in only["rules"]], ["BC-01"])
        self.assertEqual(only["rules_without_worker_state"], [])


if __name__ == "__main__":
    unittest.main()
