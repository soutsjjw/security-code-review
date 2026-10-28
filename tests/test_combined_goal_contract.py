"""Guard the combined PR #67 native-agent /goal and PR #69 evidence-recovery contract."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CombinedGoalContractTests(unittest.TestCase):
    def test_goal_preserves_native_workers_and_scoped_revision_consent(self):
        doc = (ROOT / "docs/advanced-usage.md").read_text(encoding="utf-8")
        goal = doc.split("## Codex 可選 `/goal` 完整審查指令", 1)[1].split("\n## ", 1)[0]
        for phrase in (
            "/goal 使用 $security-code-review --multi-agent --agents 3",
            "主代理", "原生協作工具", "claim-batch",
            "授權（本人明確同意）", "--integrate --allow-revision",
            "不包含 --allow-finding-revision", "Finding",
            "review_evidence_recovery.py --plan", "--restore",
            "Manifest", "Journal",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, goal)
        self.assertNotIn("維持單代理執行，不啟動子代理", goal)

    def test_skill_preserves_both_security_boundaries_and_size(self):
        data = (ROOT / "SKILL.md").read_bytes()
        skill = data.decode("utf-8")
        self.assertLessEqual(len(data), 15 * 1024)
        for phrase in (
            "只有主代理可正式 Stage/Integrate",
            "非 Git 專案不得直接降級",
            "SHA256", "evidence_integrity",
        ):
            with self.subTest(phrase=phrase):
                if phrase == "evidence_integrity":
                    self.assertIn("review_evidence_recovery.py", skill)
                else:
                    self.assertIn(phrase, skill)
        self.assertIn("--allow-finding-revision", skill)
        self.assertIn("--allow-revision", skill)

    def test_recovery_implementation_and_agent_isolation_both_remain(self):
        self.assertTrue((ROOT / "scripts/review_evidence_recovery.py").is_file())
        self.assertTrue((ROOT / "scripts/evidence_integrity.py").is_file())
        self.assertTrue((ROOT / "scripts/multi_agent.py").is_file())
        native = (ROOT / "docs/multi-agent-review.md").read_text(encoding="utf-8")
        integrity = (ROOT / "docs/evidence-integrity.md").read_text(encoding="utf-8")
        self.assertIn("sandbox", native)
        self.assertIn("不是 Git repo 本身不構成降級理由", native)
        self.assertIn("backup-restore", integrity)
        self.assertIn("prior-findings-unverified.json", integrity)


if __name__ == "__main__":
    unittest.main()
