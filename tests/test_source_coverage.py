"""完整檔案覆蓋率：以實際受測根目錄計數，避免 13/660 仍可產出正式報告。"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from source_coverage import build_source_coverage
from review_queue import build_queue, load_rules
from review_completion import completion_errors
from review_fixture import make_file_review


class SourceCoverageTests(unittest.TestCase):
    def test_660_cs_only_13_reviewed_must_not_finish(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            for i in range(660):
                (root / "src" / f"File{i:03}.cs").write_text("// fixture", encoding="utf-8")
            (root / "obj").mkdir()
            (root / "obj" / "Auto.cs").write_text("// generated", encoding="utf-8")
            inspected = [f"src/File{i:03}.cs" for i in range(13)]
            assessment = {"checks": [{"id": "AC-01", "execution": {
                "state": "completed", "inspected_paths": inspected
            }}], "file_reviews": [make_file_review(root, path, ["AC-01"]) for path in inspected]}
            coverage = build_source_coverage(assessment, root)
            self.assertEqual(coverage["source_file_count"], 660)
            self.assertEqual(coverage["reviewed_source_file_count"], 13)
            self.assertEqual(coverage["missing_source_file_count"], 647)
            self.assertEqual(coverage["missing_by_type"][".cs"], 647)
            self.assertNotIn("obj/Auto.cs", coverage["missing_source_paths"])

            _, rules = load_rules()
            by_id = {check["id"]: check for check in assessment["checks"]}
            checks = []
            for rule in rules:
                checks.append(by_id.get(rule["id"], {
                    "id": rule["id"], "execution": {
                        "state": "completed", "inspected_paths": []
                    }
                }))
            q = build_queue({"checks": checks, "file_reviews": assessment["file_reviews"]}, rules, 10, source_root=root)
            self.assertEqual(q["completed"], 70)
            self.assertFalse(q["ready_for_report"])
            self.assertEqual(q["source_coverage"]["missing_source_file_count"], 647)
            self.assertEqual(len(q["next_source_paths"]), 30)

    def test_default_and_custom_exclusions_apply_without_hiding_other_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "api").mkdir()
            (root / "unrelated").mkdir()
            (root / "api" / "A.cs").write_text("a")
            (root / "api" / "B.cs").write_text("b")
            (root / "unrelated" / "C.cs").write_text("c")
            assessment = {
                "scope_details": {
                    "projects": [{"name": "API", "path": "api"}],
                    "excluded_paths": [{"path": "unrelated", "reason": "本次明確排除"}],
                },
                "checks": [{"id": "AC-01", "execution": {
                    "state": "completed", "inspected_paths": ["api/A.cs"]
                }}],
                "file_reviews": [make_file_review(root, "api/A.cs", ["AC-01"])],
            }
            coverage = build_source_coverage(assessment, root)
            self.assertEqual(coverage["source_file_count"], 2)
            self.assertEqual(coverage["missing_source_paths"], ["api/B.cs"])
            assessment["scope_details"]["excluded_paths"] = []
            coverage = build_source_coverage(assessment, root)
            self.assertEqual(coverage["source_file_count"], 3)
            self.assertIn("unrelated/C.cs", coverage["missing_source_paths"])

    def test_pending_or_blocked_paths_never_count_as_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.cs").write_text("x")
            assessment = {"checks": [
                {"id": "AC-01", "execution": {"state": "pending", "inspected_paths": ["a.cs"]}},
                {"id": "AC-02", "execution": {"state": "blocked", "inspected_paths": ["a.cs"]}},
            ]}
            self.assertEqual(build_source_coverage(assessment, root)["missing_source_file_count"], 1)

    def test_completed_review_without_inspection_or_evidence_fails(self):
        check = {
            "id": "AC-01",
            "status": "review",
            "decision_reason": "已檢查應用程式，但缺少外部環境資料待確認",
            "execution": {"state": "completed", "methods": ["read source"],
                          "summary": "已檢查應用程式的程式碼來源及設定結構，仍待部署佐證",
                          "inspected_paths": []},
            "evidence": [],
        }
        self.assertIn("缺少實際已讀來源檔", " ".join(completion_errors([check])))
        check["execution"]["inspected_paths"] = ["a.cs"]
        self.assertEqual(completion_errors([check]), [])


if __name__ == "__main__":
    unittest.main()
