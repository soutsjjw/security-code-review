"""正式使用文件不得以開發階段代號取代實際功能名稱。"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

USER_GUIDES = (
    "SKILL.md",
    "README.md",
    "docs/advanced-usage.md",
    "docs/review-integrity-guards.md",
    "docs/control-effectiveness-review.md",
    "docs/review-decision-adjudication.md",
    "docs/adversarial-second-pass.md",
    "docs/quality-acceptance.md",
    "docs/p0-review-guards.md",  # 舊路徑只保留相容連結
    "docs/p2-control-effectiveness.md",
    "docs/p3-review-adjudication.md",
)
GUIDE_LINKS = {
    "docs/review-integrity-guards.md",
    "docs/control-effectiveness-review.md",
    "docs/review-decision-adjudication.md",
    "docs/adversarial-second-pass.md",
}
LEGACY_LINKS = {
    "docs/p0-review-guards.md": "docs/review-integrity-guards.md",
    "docs/p2-control-effectiveness.md": "docs/control-effectiveness-review.md",
    "docs/p3-review-adjudication.md": "docs/review-decision-adjudication.md",
}


class CapabilityDocumentationTests(unittest.TestCase):
    def test_public_instructions_use_capability_names_not_development_phases(self):
        for relative in USER_GUIDES:
            with self.subTest(path=relative):
                text = (ROOT / relative).read_text(encoding="utf-8")
                self.assertNotRegex(text, r"\bP[0-3]\b")
                self.assertNotRegex(text, r"\bQ[1-5]\b")
                self.assertNotRegex(text, r"\bp[0-3]-")

    def test_new_guides_exist_and_old_paths_link_to_them(self):
        for relative in GUIDE_LINKS:
            with self.subTest(path=relative):
                self.assertTrue((ROOT / relative).is_file())
        for previous, canonical in LEGACY_LINKS.items():
            with self.subTest(previous=previous):
                text = (ROOT / previous).read_text(encoding="utf-8")
                self.assertIn(Path(canonical).name, text)
                self.assertLess(len(text), 600,
                                "相容路徑應是短導引，避免兩份正式規範分歧")

    def test_links_to_new_guides_resolve_from_each_document(self):
        for relative in USER_GUIDES:
            content = (ROOT / relative).read_text(encoding="utf-8")
            for link in re.findall(r"\[[^\]]+\]\(([^)]+)\)", content):
                destination = link.split("#", 1)[0]
                if not any(destination.endswith(Path(p).name) for p in GUIDE_LINKS):
                    continue
                with self.subTest(source=relative, link=link):
                    target = ((ROOT / relative).parent / destination).resolve()
                    self.assertTrue(target.is_relative_to(ROOT.resolve()))
                    self.assertTrue(target.is_file(), str(target))
        guards = (ROOT / "docs/review-integrity-guards.md").read_text("utf-8")
        self.assertIn("## 跨檔呼叫點必須人工結案", guards)


if __name__ == "__main__":
    unittest.main()
