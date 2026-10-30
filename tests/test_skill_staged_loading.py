"""檢查精簡 Skill 的階段式文件載入契約，不能因減少 Token 而略過安全守門。"""
from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/lib"))
from validate_skill_docs import documentation_errors

STAGES = {
    "docs/python-runtime.md": ("SECURITY_CODE_REVIEW_PYTHON_PINNED", "--resolve", "--check"),
    "docs/full-review-workflow.md": ("review_queue.py", "review_log.py", "--compact"),
    "docs/source-review-guidance.md": ("file_reviews", "candidate_exclusions", "control_trace"),
    "docs/review-decision-contract.md": ("## 共同證據與結果判定", "### 判定階梯", "### 標記 `review` 前的自檢"),
    "docs/report-handoff.md": ("complete_review.py", "project.json", "HTML", "JSON"),
}


class StagedSkillTests(unittest.TestCase):
    def test_entrypoint_is_small_and_all_contracts_reachable(self):
        main = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertLessEqual(len(main.encode("utf-8")), 15 * 1024)
        self.assertEqual(documentation_errors(ROOT), [])
        self.assertIn("## 共同證據與結果判定（所有規範均適用）", main)
        self.assertIn("## 標準文件按需載入（必須執行）", main)
        for path, phrases in STAGES.items():
            with self.subTest(document=path):
                self.assertIn(f"]({path})", main)
                body = (ROOT / path).read_text(encoding="utf-8")
                for phrase in phrases:
                    self.assertIn(phrase, body)

    def test_both_modes_load_shared_decision_before_judgments(self):
        main = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("第一條規則判定之前，兩種模式", main)
        category = (ROOT / "docs/category-review.md").read_text(encoding="utf-8")
        self.assertIn("ready_for_report=false", category)
        self.assertIn("--begin-second-pass", category)
        self.assertIn("docs/category-review.md", main)
        self.assertIn("第二輪不可省略", main)
        self.assertIn("70 項", main)
        self.assertIn("100%", main)

    def test_relative_document_links_resolve(self):
        for path in ("SKILL.md", *STAGES):
            text = (ROOT / path).read_text(encoding="utf-8")
            for rel in re.findall(r"\]\(([^)#]+\.md)(?:#[^)]+)?\)", text):
                if "://" in rel or rel.startswith("#"):
                    continue
                with self.subTest(source=path, link=rel):
                    dest = ((ROOT / path).parent / rel).resolve()
                    self.assertTrue(dest.is_relative_to(ROOT.resolve()))
                    self.assertTrue(dest.is_file(), f"{path} → {rel}")

    def test_missing_stage_guide_is_an_explicit_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "SKILL.md").write_bytes((ROOT / "SKILL.md").read_bytes())
            problems = documentation_errors(root)
            self.assertTrue(any("缺少階段性載入文件" in problem for problem in problems))


if __name__ == "__main__":
    unittest.main()
