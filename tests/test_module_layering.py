"""共用底層不得反向匯入上層模組，scripts/lib/ 內不得存在任何循環匯入（含函式內延遲匯入）。"""
import ast
import contextlib
import importlib
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts/lib"
sys.path.insert(0, str(SCRIPTS))
from review_snapshot import high_tier_rules, rule_scopes, rule_tiers

# 最底層模組可匯入的審查模組上限；review_core 與 standard_guides 完全不得匯入其他審查模組。
BASE_LAYERS = {"review_core": set(), "scope_paths": set(), "standard_guides": set(),
               "control_proofs": {"source_reader"}}


def _import_graph() -> dict[str, set[str]]:
    modules = {p.stem for p in SCRIPTS.glob("*.py")}
    graph = {}
    for name in modules:
        tree = ast.parse((SCRIPTS / f"{name}.py").read_text("utf-8"))
        edges = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module in modules:
                edges.add(node.module)
            elif isinstance(node, ast.Import):
                edges.update(a.name for a in node.names if a.name in modules)
        graph[name] = edges - {name}
    return graph


def _cycles(graph: dict[str, set[str]]) -> list[set[str]]:
    index, low, stack, on_stack, found = {}, {}, [], set(), []

    def visit(node: str) -> None:
        index[node] = low[node] = len(index)
        stack.append(node)
        on_stack.add(node)
        for nxt in graph[node]:
            if nxt not in index:
                visit(nxt)
                low[node] = min(low[node], low[nxt])
            elif nxt in on_stack:
                low[node] = min(low[node], index[nxt])
        if low[node] == index[node]:
            component = set()
            while True:
                item = stack.pop()
                on_stack.discard(item)
                component.add(item)
                if item == node:
                    break
            if len(component) > 1:
                found.append(component)

    for node in sorted(graph):
        if node not in index:
            visit(node)
    return found


class ModuleLayeringTests(unittest.TestCase):
    def test_base_layers_only_import_allowed_modules(self):
        graph = _import_graph()
        for name, allowed in BASE_LAYERS.items():
            self.assertLessEqual(graph[name], allowed, name)

    def test_no_import_cycles(self):
        self.assertEqual(_cycles(_import_graph()), [])

    def test_cli_wrappers_match_lib_entry_points(self):
        # scripts/<name>.py 只是轉呼叫 lib 的入口；有 main 的 lib 模組必須都有入口，反之亦然。
        launcher_tools = {"check_python_env"}
        wrappers = {p.stem for p in (ROOT / "scripts").glob("*.py")} - launcher_tools
        entry_points = {p.stem for p in SCRIPTS.glob("*.py")
                        if "__name__ == " in p.read_text("utf-8")}
        self.assertEqual(wrappers, entry_points)
        for name in wrappers:
            body = (ROOT / "scripts" / f"{name}.py").read_text("utf-8")
            self.assertIn(f'runpy.run_module("{name}", run_name="__main__", alter_sys=True)', body, name)

    def test_importing_any_script_has_no_side_effects(self):
        # 多數 lib 模組同時是 CLI，所以 CLI 邏輯必須放在 main() 內，匯入時不得執行。
        for name in sorted(_import_graph()):
            out, err = io.StringIO(), io.StringIO()
            with self.subTest(name), patch.object(sys, "argv", [name]), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                try:
                    importlib.import_module(name)
                except SystemExit as exc:
                    self.fail(f"{name} exits on import: {exc.code}")
            self.assertEqual((out.getvalue(), err.getvalue()), ("", ""), name)

    def test_rule_scopes_come_from_master_catalog(self):
        scopes = rule_scopes()
        self.assertEqual(len(scopes), 70)
        self.assertEqual(sorted(set(scopes.values())), ["cross_file", "local", "project"])

    def test_high_risk_rules_come_from_review_tier(self):
        from adversarial_evidence import HIGH_RISK_RULES
        tiers = rule_tiers()
        self.assertEqual(len(tiers), 70)
        self.assertEqual(HIGH_RISK_RULES, high_tier_rules())
        self.assertEqual(len(HIGH_RISK_RULES), 23)
        # 類別前綴不得再自行判定高風險：同類別內仍有 standard 規則。
        self.assertIn("IN-01", HIGH_RISK_RULES)
        self.assertNotIn("IN-05", HIGH_RISK_RULES)
        for name in ("incremental_verification", "review_repair_waves"):
            body = (SCRIPTS / f"{name}.py").read_text("utf-8")
            self.assertNotRegex(body, r'\{?\(?"AC", "AU"', name)


if __name__ == "__main__":
    unittest.main()
