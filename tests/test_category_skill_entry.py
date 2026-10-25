"""Skill 分類參數與實際 CLI／文件契約一致性測試。

檢查 Codex 對話引導可在不寫入正式報告的條件下啟動分類佇列。
這是工具／說明契約測試，並非實際 70 項安全審查或模型端對端驗收。
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from review_scope import CATEGORIES, CATEGORY_COUNTS, load_catalog, parse_categories


class CategorySkillEntryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = load_catalog()
        cls.docs = {
            path: (ROOT / path).read_text(encoding="utf-8")
            for path in ("SKILL.md", "README.md",
                         "docs/advanced-usage.md", "docs/category-review.md")
        }

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.target = Path(temp.name)
        (self.target / "Safe.cs").write_text(
            "namespace Sample; public sealed class Safe { public int Number => 42; }\n",
            encoding="utf-8")

    def _cli(self, script: str, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(ROOT / "scripts" / script),
             "--target", str(self.target), *args],
            capture_output=True, encoding="utf-8", text=True,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"}, check=False,
        )

    def test_codex_usage_is_documented_with_full_and_partial_modes(self):
        skill, readme = self.docs["SKILL.md"], self.docs["README.md"]
        advanced = self.docs["docs/advanced-usage.md"]
        for content in (skill, readme, advanced):
            with self.subTest(document=content[:20]):
                self.assertIn("$security-code-review --categories AC,AU", content)
                self.assertIn("$security-code-review", content)
                self.assertIn("部分審查", content)
        self.assertIn("argument-hint: \"[專案路徑] [--categories AC,AU]\"", skill)
        self.assertIn("docs/category-review.md", skill)
        self.assertIn("docs/category-review.md", readme)
        self.assertIn("category-review.md", advanced)

    def test_ac_au_goal_keeps_all_original_review_quality_conditions(self):
        """分類 /goal 必須完整保留 0～9 審查品質要求，不得被縮減為捷徑。"""
        advanced = self.docs["docs/advanced-usage.md"]
        full_heading = "## Codex 可選 `/goal` 完整審查指令"
        partial_heading = "## Codex 可選 `/goal` 指定分類審查指令（AC、AU）"
        self.assertEqual(advanced.count(full_heading), 1)
        self.assertEqual(advanced.count(partial_heading), 1)
        full = advanced.split(full_heading, 1)[1].split(partial_heading, 1)[0]
        partial = advanced.split(partial_heading, 1)[1].split(
            "## 跨檔控制鏈的實際來源驗證", 1)[0]
        for number in range(10):
            with self.subTest(condition=number):
                pattern = rf"(?m)^{number}\. "
                self.assertRegex(full, pattern)
                self.assertRegex(partial, pattern)
        for evidence_requirement in (
            "review 比例超過 40%",
            "三題自檢",
            "open_static_questions 必須為空",
            "review_kind",
            "不得僅因未執行動態測試",
            "已知弱點未建立 Finding",
            "大量複製的檢核理由",
            "不得只修改 JSON 以通過驗證",
        ):
            with self.subTest(requirement=evidence_requirement):
                self.assertIn(evidence_requirement, full)
                self.assertIn(evidence_requirement, partial)
        self.assertIn("對目前專案執行完整、具備真實程式碼證據的 70 項", full)
        self.assertIn("ready_for_report=true", full)
        self.assertIn("analysis_prepare.py", full)
        for marker in (
            "/goal 使用 $security-code-review --categories AC,AU",
            "AC 8/8、AU 10/10",
            "review_scope.py",
            "--categories AC,AU --prepare",
            "--categories AC --begin-second-pass",
            "--categories AU --begin-second-pass",
            "--allow-revision",
            "--recover-integrity",
            "ready_for_report **固定為 false**",
            "safety_valid=true",
            "remaining_ids=[]",
            "second_pass.pending_count=0",
            "--strict-sources --categories AC,AU",
            "partial/AC/report.json",
            "partial/AU/report.json",
            "其他 52 項",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, partial)
        self.assertNotIn("0. 先執行 analysis_prepare.py", partial)
        self.assertNotIn("review_safety.py --plan", partial)
        self.assertNotIn("review_safety.py --stage", partial)
        self.assertNotIn("review_queue.py 回傳 ready_for_report=true", partial)

    def test_full_only_scripts_not_used_for_partial(self):
        skill = self.docs["SKILL.md"]
        operations = self.docs["docs/category-review.md"]
        self.assertIn("不得", operations)
        self.assertIn("analysis_prepare.py", operations)
        self.assertIn("ready_for_report=false", operations)
        self.assertIn("safety_valid=true", operations)
        self.assertIn("second_pass.pending_count=0", operations)
        self.assertIn("review_queue.py", operations)
        self.assertIn("--begin-second-pass", operations)
        self.assertIn("--stage", operations)
        self.assertIn("--integrate", operations)
        self.assertIn("--prepare", operations)
        self.assertIn("complete_review.py", operations)
        self.assertIn("validate_report.py", operations)
        self.assertIn("--strict-sources", operations)
        self.assertIn("完整模式", skill)

    def test_selected_categories_match_live_catalog_not_prose_only(self):
        for cat, count in CATEGORY_COUNTS.items():
            self.assertEqual(
                len([r for r in self.catalog["rules"] if r["category"] == cat]), count)
        self.assertEqual(sum(CATEGORY_COUNTS.values()), 70)
        self.assertEqual(parse_categories("au, ac"), ("AC", "AU"))
        for cat, count in CATEGORY_COUNTS.items():
            self.assertIn(f"{cat} {count}", self.docs["docs/category-review.md"])
        self.assertEqual(len(CATEGORIES), 10)

    def test_codex_category_plan_then_init_does_not_create_formal_review(self):
        scoped = self._cli("review_scope.py", "--categories", "AC,AU")
        self.assertEqual(scoped.returncode, 0, scoped.stderr)
        plan = json.loads(scoped.stdout)
        self.assertEqual((plan["review_mode"], plan["selected_rule_count"]), ("partial", 18))
        self.assertEqual([item["category"] for item in plan["category_reports"]], ["AC", "AU"])

        queue = self._cli("review_queue.py", "--categories", "AC,AU", "--init", "--compact")
        self.assertEqual(queue.returncode, 0, queue.stderr)
        payload = json.loads(queue.stdout)
        self.assertEqual(payload["selected_rule_count"], 18)
        self.assertEqual([q["total"] for q in payload["category_queues"]], [8, 10])
        self.assertFalse(payload["ready_for_report"])
        self.assertFalse((self.target / "reports/security-code-review/assessment.json").exists())
        for cat in ("AC", "AU"):
            path = self.target / "reports/security-code-review/partial" / cat / "assessment.json"
            self.assertTrue(path.is_file())
            self.assertEqual(json.loads(path.read_text("utf-8"))["category"], cat)

    def test_incomplete_partial_cannot_be_misreported_success(self):
        initialized = self._cli("review_queue.py", "--categories", "AC", "--init", "--compact")
        self.assertEqual(initialized.returncode, 0, initialized.stderr)
        blocked = self._cli("complete_review.py", "--categories", "AC")
        self.assertNotEqual(blocked.returncode, 0)
        self.assertFalse((self.target / "reports/security-code-review/partial/AC/report.json").exists())
        self.assertFalse((self.target / "reports/security-code-review/report.json").exists())

    def test_stale_phase_text_not_present_in_runtime_notice(self):
        result = self._cli("review_queue.py", "--categories", "AC", "--init", "--compact")
        self.assertEqual(result.returncode, 0, result.stderr)
        notice = json.loads(result.stdout)["notice"]
        self.assertIn("complete_review.py --categories", notice)
        self.assertNotIn("尚未啟用", notice)
        self.assertFalse(json.loads(result.stdout)["ready_for_report"])


if __name__ == "__main__":
    unittest.main()
