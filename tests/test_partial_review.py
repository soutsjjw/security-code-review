"""P2：分類佇列、進度隔離、來源版本防護、逐檔驗證回歸。"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from partial_review import (ScopeError, _category_dir, initialize, integrate, queue,
                            read_category, stage)
from review_scope import CATEGORIES, load_catalog
from source_coverage import build_source_coverage


class PartialReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = load_catalog()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "Safe.cs").write_text(
            "namespace Sample { public class Safe { public int Answer() => 42; } }\n",
            encoding="utf-8")
        self.formal = self.root / "reports/security-code-review/assessment.json"
        self.formal.parent.mkdir(parents=True)
        self.formal.write_text('{"official":"unchanged"}', encoding="utf-8")

    def test_ac_au_are_isolated_and_formal_untouched(self):
        created = initialize(self.root, ("AC", "AU"), self.catalog)
        self.assertEqual(created, ["AC", "AU"])
        ac = read_category(self.root, "AC", self.catalog)
        au = read_category(self.root, "AU", self.catalog)
        self.assertEqual(len(ac["checks"]), 8)
        self.assertEqual(len(au["checks"]), 10)
        self.assertEqual(ac["review_mode"], "partial")
        self.assertEqual(ac["source_snapshot_sha256"], au["source_snapshot_sha256"])
        self.assertEqual(initialize(self.root, ("AC", "AU"), self.catalog), [])
        self.assertEqual(self.formal.read_text("utf-8"), '{"official":"unchanged"}')
        self.assertFalse((self.root / "reports/security-code-review/report.json").exists())

    def test_partial_queue_is_pending_even_for_all_ten(self):
        initialize(self.root, CATEGORIES, self.catalog)
        result = queue(self.root, CATEGORIES, self.catalog, 4, compact=True)
        self.assertEqual(result["selected_rule_count"], 70)
        self.assertEqual(len(result["category_queues"]), 10)
        self.assertFalse(result["ready_for_report"])
        self.assertTrue(all(x["ready_for_report"] is False for x in result["category_queues"]))
        self.assertEqual(result["category_queues"][0]["total"], 8)
        self.assertEqual(len(result["category_queues"][0]["next_checks"]), 4)
        self.assertEqual(result["category_queues"][1]["total"], 10)
        self.assertEqual(result["category_queues"][0]["remaining_ids"][0], "AC-01")

    def test_single_category_stage_and_integrate_resume(self):
        initialize(self.root, ("AC", "AU"), self.catalog)
        pending = read_category(self.root, "AC", self.catalog)["checks"][0]
        pending["execution"]["summary"] = "已盤點 AC-01 相關候選，但尚未完成來源取證。"
        path = self.root / "payload.json"
        path.write_text(json.dumps({"checks": [pending]}), encoding="utf-8")
        staged = stage(self.root, "AC", path, self.catalog)
        with self.assertRaises(ScopeError):
            stage(self.root, "AC", path, self.catalog)
        result = integrate(self.root, "AC", self.catalog)
        self.assertEqual(result["saved_checks"], 1)
        self.assertFalse(result["ready_for_report"])
        self.assertFalse(staged.exists())
        ac = read_category(self.root, "AC", self.catalog)
        self.assertEqual(ac["checks"][0]["execution"]["summary"], pending["execution"]["summary"])
        self.assertEqual(read_category(self.root, "AU", self.catalog)["checks"][0]["id"], "AU-01")
        self.assertEqual(self.formal.read_text("utf-8"), '{"official":"unchanged"}')

    def test_payload_rejects_other_categories_and_findings(self):
        initialize(self.root, ("AC",), self.catalog)
        path = self.root / "payload.json"
        for payload in (
            {"checks": [{"id": "AU-01", "status": "pass", "execution": {"state": "pending"}}]},
            {"findings": [{"id": "F-01", "check_ids": ["AU-01"]}]},
            {"file_reviews": [{"path": "Safe.cs", "category_screening": {"AU": {}},
                               "rule_reviews": []}]},
            {"file_reviews": [{"path": "Safe.cs", "category_screening": {"AC": {"rule_ids": []}},
                               "rule_reviews": [{"rule_id": "AU-01"}]}]},
        ):
            with self.subTest(payload=payload):
                path.write_text(json.dumps(payload), encoding="utf-8")
                with self.assertRaises(ScopeError):
                    stage(self.root, "AC", path, self.catalog)
        self.assertFalse((_category_dir(self.root, "AC") / "analysis/staged/pending.json").exists())

    def test_source_modified_before_resume_or_integrate_blocks(self):
        initialize(self.root, ("AC",), self.catalog)
        ac = read_category(self.root, "AC", self.catalog)
        path = self.root / "payload.json"
        path.write_text(json.dumps({"checks": [ac["checks"][0]]}), encoding="utf-8")
        stage(self.root, "AC", path, self.catalog)
        (self.root / "Safe.cs").write_text("public class Altered { }\n", encoding="utf-8")
        with self.assertRaises(ScopeError):
            read_category(self.root, "AC", self.catalog)
        with self.assertRaises(ScopeError):
            integrate(self.root, "AC", self.catalog)
        self.assertTrue((_category_dir(self.root, "AC") / "analysis/staged/pending.json").exists())

    def test_progress_conflict_blocks_changed_base(self):
        initialize(self.root, ("AC",), self.catalog)
        ac = read_category(self.root, "AC", self.catalog)
        path = self.root / "payload.json"
        path.write_text(json.dumps({"checks": [ac["checks"][0]]}), encoding="utf-8")
        stage(self.root, "AC", path, self.catalog)
        assessment_path = _category_dir(self.root, "AC") / "assessment.json"
        tampered = json.loads(assessment_path.read_text(encoding="utf-8"))
        tampered["checks"][0]["decision_reason"] = "有人已修改進度，應拒絕舊 staged 交易"
        assessment_path.write_text(json.dumps(tampered), encoding="utf-8")
        with self.assertRaises(ScopeError):
            integrate(self.root, "AC", self.catalog)

    def test_category_only_file_review_proves_source_without_other_categories(self):
        assessment = {
            "checks": [{"id": "AC-01", "execution": {"state": "pending"}}],
            "file_reviews": [{
                "path": "Safe.cs",
                "sha256": hashlib.sha256((self.root / "Safe.cs").read_bytes()).hexdigest(),
                "summary": "已閱讀該檔案的完整邏輯與呼叫位置，未找到本分類安全控制或對外輸入。",
                "methods": ["完整來源閱讀"],
                "category_screening": {
                    "AC": {"rule_ids": [], "reason": "僅為不含身份驗證功能的一般範例類別，無 AC 控制責任"}
                },
                "rule_reviews": [], "candidate_exclusions": []
            }]
        }
        result = build_source_coverage(assessment, self.root, selected_categories=("AC",))
        self.assertEqual(result["source_file_count"], 1)
        self.assertEqual(result["reviewed_source_file_count"], 1, result["review_integrity_errors"])
        self.assertEqual(result["missing_source_file_count"], 0)
        formal = build_source_coverage(assessment, self.root)
        self.assertNotEqual(formal["review_integrity_errors"], [])
        self.assertEqual(formal["reviewed_source_file_count"], 0)

    def test_cli_classification_and_scope_restrictions(self):
        args = [sys.executable, str(ROOT / "scripts/review_queue.py"),
                "--target", str(self.root), "--categories", "AC,AU", "--init", "--compact"]
        env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
        good = subprocess.run(args, capture_output=True, text=True, encoding="utf-8",
                              env=env, check=False)
        self.assertEqual(good.returncode, 0, good.stderr)
        self.assertEqual(json.loads(good.stdout)["selected_rule_count"], 18)
        invalid = subprocess.run(args[:-2] + ["--categories", "AU"], capture_output=True,
                                 text=True, encoding="utf-8", env=env, check=False)
        self.assertNotEqual(invalid.returncode, 0)
        details = subprocess.run(args[:-2] + ["--detail-id", "IN-01"], capture_output=True,
                                 text=True, encoding="utf-8", env=env, check=False)
        self.assertNotEqual(details.returncode, 0)
        self.assertEqual(self.formal.read_text("utf-8"), '{"official":"unchanged"}')


if __name__ == "__main__":
    unittest.main()
