"""Log、精簡查詢、索引增量與停滯續跑的回歸測試。"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import review_log
from analysis_prepare import prepare
from review_queue import build_queue, load_rules
from source_coverage import provisional_source_coverage


class ReviewLogTests(unittest.TestCase):
    def test_log_only_under_reports_and_never_changes_assessment(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            evidence = root / "reports/security-code-review/assessment.json"
            evidence.parent.mkdir(parents=True)
            evidence.write_text('{"findings":[{"id":"KEEP"}]}', encoding="utf-8")
            first = review_log.start(root)
            self.assertEqual(first["status"], "running")
            review_log.command(root, "structure_index", "analysis_prepare", 1.25, 0)
            state = review_log.checkpoint(root, "first_pass",
                                          {"completed_rules": 4, "reviewed_files": 12})
            self.assertEqual(state["progress"]["completed_rules"], 4)
            self.assertEqual(state["command_seconds"]["analysis_prepare"], 1.25)
            saved = review_log.finish(root, "interrupted")
            self.assertEqual(saved["status"], "interrupted")
            next_run = review_log.start(root)
            self.assertEqual(next_run["review_id"], first["review_id"])
            self.assertNotEqual(next_run["run_id"], first["run_id"])
            self.assertEqual(json.loads(evidence.read_text("utf-8"))["findings"][0]["id"], "KEEP")
            folder = evidence.parent / "logs"
            self.assertTrue((folder / (first["run_id"] + ".jsonl")).is_file())
            self.assertTrue((folder / (first["run_id"] + "-summary.json")).is_file())
            self.assertTrue((folder / "latest.json").is_file())
            self.assertEqual(json.loads((folder / "latest.json").read_text("utf-8"))["run_id"],
                             next_run["run_id"])

    def test_no_content_field_allowed_in_checkpoint(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            review_log.start(root)
            with self.assertRaises(ValueError):
                review_log.checkpoint(root, "first_pass", {"secret": 1})
            with self.assertRaises(ValueError):
                review_log.checkpoint(root, "first_pass", {"completed_rules": -1})
            with self.assertRaises(ValueError):
                review_log.checkpoint(root, "first_pass", {"completed_rules": True})
            self.assertNotIn("secret", (root / "reports/security-code-review/logs/latest.json")
                             .read_text("utf-8"))

    def test_stall_requires_both_time_and_no_progress_threshold(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with patch("review_log._clock", return_value=0.0):
                review_log.start(root)
                for _ in range(6):
                    state = review_log.checkpoint(root, "first_pass", {"completed_rules": 0})
                self.assertEqual(state["status"], "running")
            with patch("review_log._clock", return_value=1000.0):
                state = review_log.checkpoint(root, "first_pass", {"completed_rules": 0})
                self.assertEqual(state["status"], "stalled")
                old_id = state["run_id"]
                resumed = review_log.start(root)
            self.assertNotEqual(resumed["run_id"], old_id)
            self.assertEqual(resumed["review_id"], state["review_id"])
            self.assertEqual(json.loads((root / "reports/security-code-review/logs" /
                                         (old_id + "-summary.json")).read_text("utf-8"))["status"],
                             "interrupted")

    def test_progress_resets_stall_counter_and_only_report_success_auto_finishes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "reports/security-code-review").mkdir(parents=True)
            review_log.start(root)
            with patch("review_log._clock", return_value=0.0):
                review_log.checkpoint(root, "first_pass", {"reviewed_files": 10})
            with patch("review_log._clock", return_value=2000.0):
                state = review_log.checkpoint(root, "first_pass", {"reviewed_files": 11})
            self.assertEqual(state["no_progress_checkpoints"], 0)
            review_log._log_best_effort(root, "report", "complete_review", 2, 1)
            self.assertEqual(json.loads((root / "reports/security-code-review/logs/latest.json")
                                         .read_text("utf-8"))["status"], "running")
            review_log._log_best_effort(root, "report", "complete_review", 2, 0)
            self.assertEqual(json.loads((root / "reports/security-code-review/logs/latest.json")
                                         .read_text("utf-8"))["status"], "completed")


class PerformanceSafetyTests(unittest.TestCase):
    def test_compact_is_provisional_never_calls_complete_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Api.cs").write_text("public class Api { }", encoding="utf-8")
            _, rules = load_rules()
            data = json.loads((ROOT / "examples/assessment.example.json").read_text("utf-8"))
            with patch("review_queue.build_source_coverage", side_effect=AssertionError("strict")), \
                 patch("review_queue.safety_errors", side_effect=AssertionError("safety")), \
                 patch("review_queue.load_tacert_v2_checks", side_effect=AssertionError("standards")):
                result = build_queue(data, rules, 5, source_root=root, compact=True)
            self.assertFalse(result["ready_for_report"])
            self.assertTrue(result["validation_deferred"])
            self.assertFalse(result["source_coverage"]["verified"])
            self.assertEqual(result["source_coverage"]["missing_source_file_count"], 1)
            self.assertEqual(result["next_source_paths"], ["Api.cs"])

    def test_rule_detail_skips_global_validation_but_keeps_guidance(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Api.cs").write_text("public class Api { }", encoding="utf-8")
            _, rules = load_rules()
            data = json.loads((ROOT / "examples/assessment.example.json").read_text("utf-8"))
            with patch("review_queue.build_source_coverage", side_effect=AssertionError("strict")), \
                 patch("review_queue.safety_errors", side_effect=AssertionError("safety")):
                result = build_queue(data, rules, 1, source_root=root, detail_id="AC-01")
            self.assertTrue(result["validation_deferred"])
            self.assertFalse(result["ready_for_report"])
            self.assertIn("decision_guidance", result["next_checks"][0])

    def test_preview_reacts_to_added_file_and_cannot_fake_validated(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "A.cs").write_text("class A {}", encoding="utf-8")
            data = {"checks": [], "file_reviews": []}
            first = provisional_source_coverage(data, root)
            self.assertEqual(first["missing_source_file_count"], 1)
            (root / "B.cs").write_text("class B {}", encoding="utf-8")
            second = provisional_source_coverage(data, root)
            self.assertEqual(second["missing_source_file_count"], 2)
            self.assertFalse(second["verified"])

    def test_unchanged_snapshot_reuses_relations_and_source_change_invalidates(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Test.csproj").write_text(
                '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
                '<TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>',
                encoding="utf-8")
            (root / "Test.cs").write_text("public class Test {}", encoding="utf-8")
            with patch("analysis_prepare.probe_roslyn", return_value={"available": False}), \
                 patch("analysis_prepare.probe_codegraph", return_value={"available": False}):
                first = prepare(root, "full")
                self.assertFalse(first["relationships_reused"])
                with patch("analysis_prepare.build_relationships",
                           side_effect=AssertionError("unnecessary rebuild")):
                    second = prepare(root, "incremental")
                self.assertTrue(second["relationships_reused"])
                self.assertEqual(second["changed_file_count"], 0)


if __name__ == "__main__":
    unittest.main()
