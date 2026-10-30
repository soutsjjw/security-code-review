"""70 項規則 Markdown 必須能由 rules.json 原樣重新產生，任何手改或主檔變更都要被擋下。"""
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/lib"))
from render_rules_markdown import markdown_errors, render


class RenderRulesMarkdownTests(unittest.TestCase):
    def _copy(self, root: Path) -> None:
        (root / "docs").mkdir()
        shutil.copyfile(ROOT / "rules.json", root / "rules.json")
        shutil.copyfile(ROOT / "docs/70-rules-standardized.md", root / "docs/70-rules-standardized.md")

    def test_repository_markdown_matches_rules_json(self):
        self.assertEqual(markdown_errors(ROOT), [])

    def test_rule_change_without_regeneration_is_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            self._copy(root)
            catalog = json.loads((root / "rules.json").read_text("utf-8"))
            catalog["rules"][0]["manual_review"] = "已變更"
            (root / "rules.json").write_text(json.dumps(catalog, ensure_ascii=False), encoding="utf-8")
            self.assertEqual(len(markdown_errors(root)), 1)
            (root / "docs/70-rules-standardized.md").write_bytes(render(catalog).encode("utf-8"))
            self.assertEqual(markdown_errors(root), [])

    def test_hand_edit_is_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            self._copy(root)
            doc = root / "docs/70-rules-standardized.md"
            doc.write_text(doc.read_text("utf-8").replace("AC-01 Session", "AC-01 手改", 1), encoding="utf-8")
            self.assertEqual(len(markdown_errors(root)), 1)


if __name__ == "__main__":
    unittest.main()
