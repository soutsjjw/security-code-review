"""審查範圍計數、去重、排除與路徑安全回歸測試。"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from scope_inventory import build_scope_inventory
from review_fixture import make_file_review


class ScopeInventoryTests(unittest.TestCase):
    def test_dedup_projects_and_exclusions(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "src" / "API").mkdir(parents=True)
            (root / "src" / "Core").mkdir()
            (root / "obj").mkdir()
            (root / ".github").mkdir()
            (root / "src" / "API" / "app.cs").write_text("a")
            (root / "src" / "Core" / "model.cs").write_text("b")
            (root / "obj" / "generated.cs").write_text("c")
            (root / ".github" / "workflow.yml").write_text("d")
            data = {
                "scope_details": {
                    "projects": [{"name": "API", "path": "src/API"}, {"name": "Core", "path": "src/Core"}],
                    "excluded_paths": [{"path": "src/Core", "reason": "本次未納入"}]
                },
                "checks": [
                    {"id": "AC-01", "execution": {"state": "completed", "inspected_paths": ["src/API/app.cs"]}},
                    {"id": "AU-01", "execution": {"state": "completed", "inspected_paths": ["src/API/app.cs"]}},
                    {"id": "IN-01", "execution": {"state": "pending", "inspected_paths": [".github/workflow.yml"]}}
                ],
            }
            data["file_reviews"] = [make_file_review(root, "src/API/app.cs", ["AC-01", "AU-01"])]
            out = build_scope_inventory(data, root)
            self.assertEqual(out["reviewed_file_count"], 1)
            self.assertEqual(out["reviewed_project_count"], 1)
            self.assertEqual(out["declared_project_count"], 2)
            self.assertEqual(out["excluded_file_count"], 2)
            self.assertEqual(out["eligible_file_count"], 2)
            self.assertEqual(out["reviewed_files"][0]["check_ids"], ["AC-01", "AU-01"])

    def test_report_artifacts_do_not_change_inventory(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "app.cs").write_text("source", encoding="utf-8")
            output = root / "custom-output"
            output.mkdir()
            report = output / "report.json"
            html = output / "CodeReview_20261018.html"
            assessment = {"checks": [{"id": "AC-01", "execution": {
                "state": "completed", "inspected_paths": ["app.cs"]}}]}
            assessment["file_reviews"] = [make_file_review(root, "app.cs", ["AC-01"])]
            artifacts = (report, html)
            before = build_scope_inventory(assessment, root, ignored_artifacts=artifacts)
            report.write_text("{}", encoding="utf-8")
            html.write_text("<!doctype html>", encoding="utf-8")
            after = build_scope_inventory(assessment, root, ignored_artifacts=artifacts)
            self.assertEqual(before, after)
            self.assertEqual(after["reviewed_file_count"], 1)
            self.assertEqual(after["inventory_file_count"], 1)
            self.assertNotEqual(build_scope_inventory(assessment, root), before)

    def test_eligible_gap_lists_every_path_and_explains_source_coverage(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "app.cs").write_text("class Sample {}", encoding="utf-8")
            (root / "README.md").write_text("docs", encoding="utf-8")
            (root / "image.png").write_bytes(b"png")
            (root / "pipeline.yml").write_text("steps: []", encoding="utf-8")
            assessment = {"checks": [], "file_reviews": [make_file_review(root, "app.cs", ())]}
            result = build_scope_inventory(assessment, root)
            self.assertEqual(result["eligible_file_count"], 4)
            self.assertEqual(result["reviewed_file_count"], 1)
            self.assertEqual(result["source_file_count"], 2)
            self.assertEqual(result["reviewed_source_file_count"], 1)
            self.assertEqual(result["missing_source_file_count"], 1)
            self.assertEqual(result["eligible_unreviewed_file_count"], 3)
            listed = {row["path"]: row["reason"] for row in result["eligible_unreviewed_files"]}
            self.assertEqual(set(listed), {"README.md", "image.png", "pipeline.yml"})
            self.assertIn("應審查來源檔", listed["pipeline.yml"])
            self.assertIn("非強制逐檔", listed["README.md"])

    def test_unknown_project_count(self):
        with tempfile.TemporaryDirectory() as t:
            out = build_scope_inventory({"checks": []}, Path(t))
            self.assertIsNone(out["reviewed_project_count"])
            self.assertEqual(out["reviewed_file_count"], 0)

    def test_reject_outside_excluded_or_missing(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "bin").mkdir()
            (root / "bin" / "generated.cs").write_text("x")
            for bad in ("../outside.cs", "bin/generated.cs", "missing.cs", "/etc/passwd"):
                with self.subTest(path=bad):
                    data = {"checks": [{"id": "AC-01", "execution": {
                        "state": "completed", "inspected_paths": [bad]}}]}
                    with self.assertRaises(ValueError):
                        build_scope_inventory(data, root)


if __name__ == "__main__":
    unittest.main()
