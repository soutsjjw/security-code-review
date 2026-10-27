"""Check the Codex-native orchestration contract stays aligned across entrypoints.

These static tests do not claim any Codex executor or sandbox capability.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SKILL = (ROOT / "SKILL.md").read_text(encoding="utf-8")
ADVANCED = (ROOT / "docs/advanced-usage.md").read_text(encoding="utf-8")
NATIVE = (ROOT / "docs/multi-agent-review.md").read_text(encoding="utf-8")


class NativeCodexOrchestrationDocsTests(unittest.TestCase):
    def test_goal_explicitly_opts_in_to_three_workers(self):
        self.assertIn(
            "/goal 使用 $security-code-review --multi-agent --agents 3 Skill",
            ADVANCED)
        self.assertIn("一般 `$security-code-review` 仍預設單代理", ADVANCED)
        self.assertIn("分類 `--categories` 不啟用多代理", ADVANCED)

    def test_main_agent_must_use_real_tools_not_invent_worker_identity(self):
        for source in (SKILL, ADVANCED, NATIVE):
            self.assertIn("原生", source)
            self.assertIn("agent", source)
            self.assertIn("單代理", source)
        self.assertIn("`spawn_agent`", NATIVE)
        self.assertIn("`--claim-batch`", ADVANCED)
        self.assertIn("待命", NATIVE)
        self.assertIn("實際", NATIVE)
        self.assertIn("不能只列出派工清單", ADVANCED)
        self.assertIn("不得憑空宣稱工具存在", NATIVE)
        self.assertIn("prompt 禁寫", NATIVE.lower().replace("「不得寫入」", "禁寫"))

    def test_no_worker_direct_formal_write_and_no_skipped_second_pass(self):
        for source in (ADVANCED, NATIVE):
            self.assertIn("`--accept-stdin`", source)
            self.assertIn("`--begin-integration`", source)
            self.assertIn("`--commit-integration`", source)
            self.assertIn("`multi_agent_second_pass.py`", source)
            self.assertIn("Manifest", source)
        self.assertIn("不得宣稱盲審", ADVANCED)
        self.assertIn("不得稱獨立盲審", NATIVE)
        self.assertIn("不得自行", SKILL)


if __name__ == "__main__":
    unittest.main()
