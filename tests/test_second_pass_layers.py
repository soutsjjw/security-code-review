"""分層第二輪計畫與抽樣完整性單元測試。"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from second_pass_layers import RESERVED, build_plan, layered_errors, record_errors, worklist
from adversarial_recheck import digest
from control_effectiveness import snapshot_fingerprint
from review_safety import _write, report_dir, stage, integrate


class LayeredTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root = Path(t.name)
        self.paths = ["src/AccessController.cs", "src/ConfigLoader.cs", "src/PlainModel.cs"]
        for name in self.paths:
            p = self.root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("public class Example { public bool Check(int x) { return x > 0; } }\n", "utf-8")
        self.snapshot = {"git_revision": "unit-test", "source_hashes": {
            p: "test-" + p for p in self.paths}, "excluded_paths": []}
        self.checks = [{"id": "R-%02d" % i, "status": "na",
                        "execution": {"state": "completed", "inspected_paths": self.paths},
                        "evidence": [{"kind": "source", "path": self.paths[0],
                                      "line_start": 1, "line_end": 1}]}
                       for i in range(70)]
        self.assessment = {"checks": self.checks, "findings": [], "file_reviews": []}
        self.baseline = {"schema_version": 1, "snapshot_fingerprint":
                         snapshot_fingerprint(self.snapshot),
                         "checks": {c["id"]: {"digest": digest(c), "status": "na"}
                                    for c in self.checks}}
        self.plan = build_plan(self.assessment, self.baseline, self.snapshot,
                               sample_limit=10, sample_rate=0.3)
        self.records = {RESERVED: {"plan": self.plan, "samples": {}}}
        _write(report_dir(self.root) / "analysis/review-snapshot.json", self.snapshot)
        _write(report_dir(self.root) / "analysis/first-pass-baseline.json", self.baseline)
        _write(report_dir(self.root) / "analysis/adversarial-reviews.json", self.records)

    def sample(self, path):
        return {"outcome": "no_new_issue",
                "inspection_summary": "已實際核對設定讀取、外部輸入與驗證分支，確認沒有新的權限繞過或不安全預設值。" ,
                "evidence": {"kind": "source", "path": path, "line_start": 1,
                             "line_end": 1}}

    def test_plan_is_deterministic_and_does_not_reveal_verdict(self):
        self.assertEqual(self.plan, build_plan(self.assessment, self.baseline, self.snapshot,
                                               sample_limit=10, sample_rate=0.3))
        self.assertEqual(len(self.plan["rules"]), 70)
        self.assertNotIn("status", json.dumps(self.plan))
        self.assertEqual([x["path"] for x in self.plan["sampling"]],
                         ["src/ConfigLoader.cs"])

    def test_sample_requires_valid_line_and_all_selected_paths(self):
        path = self.plan["sampling"][0]["path"]
        self.assertIn("尚未完成", str(layered_errors(
            self.root, self.assessment, self.baseline, self.snapshot, self.records)))
        wrong = self.sample(path)
        wrong["evidence"]["line_end"] = 999
        self.assertIn("超出實際來源行號", str(record_errors(
            self.root, path, wrong, self.plan, self.snapshot, self.assessment)))
        self.assertIn("不在固定獨立樣本清單", str(record_errors(
            self.root, self.paths[2], self.sample(self.paths[2]),
            self.plan, self.snapshot, self.assessment)))
        self.records[RESERVED]["samples"][path] = self.sample(path)
        self.assertEqual(layered_errors(self.root, self.assessment, self.baseline,
                                        self.snapshot, self.records), [])

    def test_worklist_is_bounded_and_resumable(self):
        first = worklist(self.root)
        self.assertTrue(first["ready"])
        self.assertLessEqual(len(first["rule_tasks"]), 8)
        self.assertLessEqual(len(first["targeted_paths"]), 16)
        self.records["R-00"] = {"baseline_digest": self.baseline["checks"]["R-00"]["digest"]}
        _write(report_dir(self.root) / "analysis/adversarial-reviews.json", self.records)
        self.assertEqual(worklist(self.root)["rules_pending"], 70)
        self.records["R-00"].update({
            "final_digest": digest(self.checks[0]), "hypotheses": [{}],
            "open_issues": [],
        })
        _write(report_dir(self.root) / "analysis/adversarial-reviews.json", self.records)
        self.assertEqual(worklist(self.root)["rules_pending"], 69)

    def test_atomic_sample_integration_rejects_conflicts(self):
        _write(report_dir(self.root) / "assessment.json", self.assessment)
        path = self.plan["sampling"][0]["path"]
        draft = report_dir(self.root) / "sample-draft.json"
        _write(draft, {"second_pass_samples": {path: self.sample(path)}})
        with patch("review_safety.snapshot_errors", return_value=[]):
            stage(self.root, draft)
            integrate(self.root)
            updated = self.sample(path)
            updated["inspection_summary"] += "，並重查其他分支"
            _write(draft, {"second_pass_samples": {path: updated}})
            stage(self.root, draft)
            with self.assertRaisesRegex(ValueError, "紀錄衝突"):
                integrate(self.root)


if __name__ == "__main__":
    unittest.main()
