"""防止 Codex 多代理指令退回僅分片或誤以 Git 目錄為啟動前提。"""
from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class CodexNativeSubagentContractTests(unittest.TestCase):
    @staticmethod
    def guide(relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_skill_requires_actual_native_spawn(self):
        skill = self.guide("SKILL.md")
        self.assertIn("## Codex 完整模式的原生子代理啟動", skill)
        self.assertIn("原生子代理工具實際啟動", skill)
        self.assertIn("file_review_skeleton.py --workers N", skill)
        self.assertIn("只是分片，不是啟動代理", skill)
        self.assertIn("主代理", skill)
        self.assertIn("唯一", skill)
        self.assertIn("SHA256", skill)
        self.assertIn("不得因不是 Git repo 自動降級", skill)

    def test_goal_must_not_disable_subagents(self):
        advanced = self.guide("docs/advanced-usage.md")
        goal = advanced.split("## Codex 可選 `/goal` 完整審查指令", 1)[1].split("\n## ", 1)[0]
        self.assertIn("真正啟動 Codex 原生主代理 + N 名唯讀子代理", goal)
        self.assertIn("Git worktree", goal)
        self.assertIn("原生子代理工具缺失", goal)
        self.assertNotIn("維持單代理執行，不啟動子代理", goal)

    def test_work_shards_are_not_confused_with_agents(self):
        guide = self.guide("docs/review-performance.md")
        self.assertIn("本 Skill 的 Python 腳本不具備啟動模型代理的權限", guide)
        self.assertIn("不會自行啟動代理", guide)
        self.assertIn("--workers 4 --worker-id 3", guide)
        self.assertIn("主代理等待所有子代理回報", guide)
        self.assertIn("只有**原生子代理功能不存在", guide)
        self.assertIn("不是 Git repo", guide)
        readme = self.guide("README.md")
        self.assertIn("## Codex 唯讀多代理與安全審查完整性守門", readme)
        self.assertNotIn("本次強化仍採用**單代理逐檔審查**", readme)


if __name__ == "__main__":
    unittest.main()
