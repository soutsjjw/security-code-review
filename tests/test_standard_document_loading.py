"""P5：從每條規則的真實標準映射回傳應按需載入的 Markdown 文件。"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from review_queue import STANDARD_GUIDES, build_queue, load_rules
from validate_skill_docs import documentation_errors


class StandardGuidesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _, cls.rules = load_rules()
        cls.assessment = {
            "checks": [
                {"id": rule["id"], "execution": {"state": "pending"}}
                for rule in cls.rules
            ],
            "findings": [],
        }

    def test_document_links_and_catalogs_are_consistent(self):
        self.assertEqual(documentation_errors(ROOT), [])
        self.assertEqual(len(STANDARD_GUIDES), 6)

    def test_detail_id_lists_required_guides_from_rule_mappings(self):
        all_checks = build_queue(self.assessment, self.rules, batch_size=70)["next_checks"]
        # 每種標準至少找到一個有實際映射的規則，再用單項 detail-id 驗證輸出。
        for field, path in STANDARD_GUIDES.items():
            matches = [row for row in all_checks if row.get(field)]
            self.assertTrue(matches, f"{field} 沒有可驗證的規則映射")
            with self.subTest(field=field):
                detail = build_queue(
                    self.assessment, self.rules, batch_size=1,
                    detail_id=matches[0]["id"],
                )["next_checks"][0]
                expected = [
                    p for key, p in STANDARD_GUIDES.items() if detail.get(key)
                ]
                self.assertEqual(detail["standard_documents"], expected)
                self.assertIn(path, expected)
                self.assertTrue(all((ROOT / p).is_file() for p in expected))

    def test_compact_queue_keeps_token_saving_and_points_to_detail_id(self):
        compact = build_queue(self.assessment, self.rules, batch_size=2, compact=True)
        self.assertEqual(len(compact["next_checks"]), 2)
        self.assertNotIn("standard_documents", compact["next_checks"][0])
        self.assertIn("--detail-id", compact["instruction"])

    def test_missing_standard_doc_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SKILL.md").write_text((ROOT / "SKILL.md").read_text("utf-8"), encoding="utf-8")
            self.assertTrue(any("缺少按需載入文件" in e for e in documentation_errors(root)))


if __name__ == "__main__":
    unittest.main()
