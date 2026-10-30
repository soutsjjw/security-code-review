"""安全效能與唯讀工作分片的回歸測試：不得用快取或預覽繞過驗證。"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/lib"))

import review_log
from analysis_prepare import _run_roslyn
from file_review_skeleton import INDEX, skeleton
from review_queue import build_queue, load_rules
from source_reader import source_digest


class PerformanceQueueTests(unittest.TestCase):
    def test_all_completed_preview_never_calls_formal_gate(self):
        _, rules = load_rules()
        data = json.loads((ROOT / "examples/assessment.example.json").read_text("utf-8"))
        for check in data["checks"]:
            check["execution"]["state"] = "completed"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Api.cs").write_text("class Api {}", encoding="utf-8")
            with patch("review_queue.build_source_coverage",
                       side_effect=AssertionError("正式守門不得用於 compact")), \
                 patch("review_queue.decision_quality_errors",
                       side_effect=AssertionError("正式判定品質不可用於 compact")), \
                 patch("review_queue.safety_errors",
                       side_effect=AssertionError("正式安全檢核不可用於 compact")):
                out = build_queue(data, rules, 8, source_root=root, compact=True)
            self.assertFalse(out["ready_for_report"])
            self.assertTrue(out["validation_deferred"])
            self.assertFalse(out["source_coverage"]["verified"])
            self.assertEqual(out["source_coverage"]["missing_source_file_count"], 1)

    def test_source_batch_and_cost_profile(self):
        _, rules = load_rules()
        data = json.loads((ROOT / "examples/assessment.example.json").read_text("utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("A.cs", "B.cs", "C.cs"):
                (root / name).write_text("public class " + name[0] + " {}", encoding="utf-8")
            profile = {}
            out = build_queue(data, rules, 5, source_root=root, compact=True,
                              source_batch_size=2, profile=profile)
            self.assertEqual(len(out["next_source_paths"]), 2)
            self.assertTrue({"coverage", "source_candidates", "diagnostics",
                             "queue_total"} <= set(profile))
            self.assertTrue(all(v >= 0 for v in profile.values()))
            self.assertFalse(out["ready_for_report"])


class PerformanceLogTests(unittest.TestCase):
    def test_stalled_run_rejects_command_without_running_main(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch("review_log._clock", return_value=0.0):
                review_log.start(root)
                for _ in range(4):
                    review_log.checkpoint(root, "queue", {"completed_rules": 0})
            with patch("review_log._clock", return_value=1000.0):
                stalled = review_log.checkpoint(root, "queue", {"completed_rules": 0})
            self.assertEqual(stalled["status"], "stalled")
            called = []
            with patch.object(sys, "argv", ["review_queue.py", "--target", str(root), "--compact"]):
                result = review_log.logged_main(lambda: called.append(1) or 0, "queue")
            self.assertEqual(result, 3)
            self.assertFalse(called)
            self.assertEqual(review_log.start(root)["status"], "running")
            with patch.object(sys, "argv", ["review_queue.py", "--target", str(root), "--compact"]):
                self.assertEqual(review_log.logged_main(lambda: 0, "queue"), 0)

    def test_verified_coverage_and_regressions_are_distinct_from_preview(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = review_log.start(root)
            review_log.observe_coverage(root, recorded=5, verified=3)
            review_log.observe_coverage(root, recorded=5, verified=2)
            review_log.record_profile(root, "queue", "query",
                                      {"coverage": 0.12, "diagnostics": 0.15})
            log = root / "reports/security-code-review/logs" / (state["run_id"] + ".jsonl")
            events = [json.loads(row) for row in log.read_text("utf-8").splitlines()]
            self.assertEqual(sum(e["event"] == "verified_coverage_regression"
                                 for e in events), 1)
            self.assertTrue(any(e["event"] == "query_profile" for e in events))
            latest = json.loads((log.parent / "latest.json").read_text("utf-8"))
            self.assertEqual(latest["coverage_observation"]["verified_file_reviews"], 2)
            self.assertEqual(latest["coverage_observation"]["unverified_file_reviews"], 3)
            self.assertNotIn("verified_file_reviews", latest["progress"])

    def test_checkpoint_regression_is_recorded_not_hidden(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = review_log.start(root)
            review_log.checkpoint(root, "first_pass", {"reviewed_files": 3})
            review_log.checkpoint(root, "first_pass", {"reviewed_files": 2})
            events = (root / "reports/security-code-review/logs" /
                      (state["run_id"] + ".jsonl")).read_text("utf-8")
            self.assertIn("progress_regression", events)


class SourceSkeletonTests(unittest.TestCase):
    def create_fixture(self, root: Path) -> None:
        hashes = {}
        for n in range(8):
            p = root / f"Service{n}.cs"
            p.write_text(f"public class Service{n} {{}}", encoding="utf-8")
            hashes[p.name] = source_digest(p.read_bytes())
        index = root / INDEX
        index.parent.mkdir(parents=True)
        index.write_text(json.dumps({
            "source_hashes": hashes,
            "rule_candidates": {"Service0.cs": [{"rule_id": "AC-04", "line": 1}]},
            "roslyn_files": {"Service0.cs": {"methods": [{"name": "Run"}]}},
            "cross_file_call_hints": {"Service0.cs": [{"id": "callsite-1"}]},
        }), encoding="utf-8")
        report = root / "reports/security-code-review"
        (report / "assessment.json").write_text(
            json.dumps({"checks": [], "file_reviews": []}), encoding="utf-8")
        (report / "analysis/review-snapshot.json").write_text(
            json.dumps({"source_hashes": hashes}), encoding="utf-8")

    def test_source_shards_have_no_overlap_and_are_sha_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.create_fixture(root)
            first = skeleton(root, batch_size=30, workers=2, worker_id=0)
            second = skeleton(root, batch_size=30, workers=2, worker_id=1)
            one = {row["path"] for row in first["files"]}
            two = {row["path"] for row in second["files"]}
            self.assertFalse(one & two)
            self.assertEqual(len(one | two), 8)
            self.assertFalse(first["ready_for_report"])
            all_rows = first["files"] + second["files"]
            self.assertTrue(all(row["must_read_source"] for row in all_rows))
            record = next(row for row in all_rows if row["path"] == "Service0.cs")
            self.assertEqual(record["roslyn_methods"][0]["name"], "Run")
            self.assertEqual(record["cross_file_callsite_ids"], ["callsite-1"])
            (root / "Service0.cs").write_text("changed", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "SHA256"):
                skeleton(root, requested_paths=["Service0.cs"])

    def test_worker_pagination_covers_all_without_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.create_fixture(root)
            rows = []
            for worker_id in range(3):
                offset = 0
                while True:
                    page = skeleton(root, workers=3, worker_id=worker_id,
                                    batch_size=2, offset=offset)
                    rows.extend(row["path"] for row in page["files"])
                    if page["next_offset"] is None:
                        break
                    self.assertGreater(page["next_offset"], offset)
                    offset = page["next_offset"]
            self.assertEqual(len(rows), 8)
            self.assertEqual(len(set(rows)), 8)
            self.assertFalse((root / "reports/security-code-review/analysis/staged").exists())

    def test_invalid_requested_path_cannot_escape_source_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.create_fixture(root)
            with self.assertRaises(ValueError):
                skeleton(root, requested_paths=["../secrets.txt"])


class RoslynBuildCacheTests(unittest.TestCase):
    def test_sdk_and_skill_bound_cache_reuses_compilation_and_detects_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe = {"available": True, "target_framework": "net8.0",
                     "sdk_version": "8.0.100", "executable": "dotnet"}
            calls = []
            binary = []

            def fake_run(args, **kwargs):
                calls.append(args[1])
                if args[1] == "--version":
                    return subprocess.CompletedProcess(args, 0, stdout="8.0.100\n", stderr="")
                if args[1] == "build":
                    # The CLI runs in isolated scratch; binary belongs to the
                    # SDK/version-specific *project* cache directory.
                    dll = Path(args[2]).parent / "bin/Release/net8.0/roslyn-indexer.dll"
                    dll.parent.mkdir(parents=True, exist_ok=True)
                    dll.write_bytes(b"compiled")
                    binary.append(dll)
                    return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
                return subprocess.CompletedProcess(
                    args, 0, stdout='SCROSLYN_JSON:{"files":[{"path":"Service.cs"}],"errors":[]}\n',
                    stderr="")

            with patch("analysis_prepare.Path.home", return_value=root / "home"), \
                 patch.dict("os.environ", {"SECURITY_CODE_REVIEW_ROSLYN_CACHE": "1"}), \
                 patch("analysis_prepare.subprocess.run", side_effect=fake_run):
                for _ in range(2):
                    result, errors = _run_roslyn(root, ["Service.cs"], probe)
                    self.assertEqual(errors, [])
                    self.assertIn("Service.cs", result)
                self.assertEqual(calls.count("build"), 1)
                binary[0].write_bytes(b"tampered")
                _run_roslyn(root, ["Service.cs"], probe)
                self.assertEqual(calls.count("build"), 2)


if __name__ == "__main__":
    unittest.main()
