"""共用底層不得反向匯入上層模組，且循環匯入只能減少、不得新增。"""
import ast
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
from review_safety import rule_scopes

# 只允許匯入 source_reader 的底層模組；review_core 完全不得匯入其他審查模組。
BASE_LAYERS = {"review_core": set(), "scope_paths": set(), "control_proofs": {"source_reader"}}
# 既有循環仍靠函式內延遲匯入，且測試依賴其 patch 目標；拆除時請同步縮小此清單。
KNOWN_CYCLES = [
    {"adversarial_quality", "adversarial_recheck", "analysis_prepare", "review_safety"},
    {"partial_review", "partial_review_safety", "review_queue"},
    {"review_repair_waves", "review_waves_abort", "review_waves_lifecycle"},
]


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

    def test_no_new_import_cycles(self):
        for cycle in _cycles(_import_graph()):
            self.assertIn(cycle, KNOWN_CYCLES)

    def test_rule_scopes_come_from_master_catalog(self):
        scopes = rule_scopes()
        self.assertEqual(len(scopes), 70)
        self.assertEqual(sorted(set(scopes.values())), ["cross_file", "local", "project"])


if __name__ == "__main__":
    unittest.main()
