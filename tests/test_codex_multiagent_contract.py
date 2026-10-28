"""PR #68: Codex 原生委派與非 Git 專案安全回退契約回歸測試。

These tests verify static contracts; they do not simulate or claim successful
real Codex worker execution. Runtime acceptance still needs a read-only probe.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


class CodexNativeSubagentContractTests(unittest.TestCase):
    def test_skill_explicitly_opts_in_and_disallows_fake_spawn(self):
        skill = read("SKILL.md")
        self.assertIn("--multi-agent --agents 3", skill)
        self.assertIn("原生工具", skill)
        self.assertIn("只有主代理可正式 Stage/Integrate", skill)
        self.assertIn("非 Git 專案不得直接降級", skill)
        self.assertIn("SHA256", skill)
        self.assertIn("能力不足即記錄原因並降級單代理", skill)

    def test_goal_uses_native_dispatch_and_keeps_main_writer(self):
        advanced = read("docs/advanced-usage.md")
        section = advanced.split("## Codex 可選 `/goal` 完整審查指令", 1)[1].split("\n## ", 1)[0]
        self.assertIn("/goal 使用 $security-code-review --multi-agent --agents 3", section)
        self.assertIn("原生協作工具", section)
        self.assertIn("主代理", section)
        self.assertIn("非 Git 專案不構成子代理降級條件", section)
        self.assertNotIn("維持單代理執行，不啟動子代理", section)

    def test_gitless_not_auto_disabled_in_runtime_plan(self):
        script = read("scripts/multi_agent.py")
        self.assertIn("enabled = not probe_errors(root, probe)", script)
        self.assertNotIn('and _git_state(root)["head"] is not None', script)
        self.assertIn('return {"head": None, "worktree_digest": None}', script)
        native = read("docs/multi-agent-review.md")
        self.assertIn("不是 Git repo 本身不構成降級理由", native)
        self.assertIn("sandbox", native)

    def test_shards_are_not_real_model_agents(self):
        guide = read("docs/review-performance.md")
        self.assertIn("不會啟動 Codex 子代理", guide)
        self.assertIn("multi_agent.py", guide)
        readme = read("README.md")
        self.assertIn("受控唯讀多代理與資安審查完整性守門", readme)
        self.assertIn("不是 Git repo 不能單獨作為降級理由", readme)
        self.assertNotIn("本次強化仍採用**單代理逐檔審查**", readme)


if __name__ == "__main__":
    unittest.main()
