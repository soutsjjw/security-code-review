"""共用底層不得反向匯入上層模組，scripts/ 內不得存在任何循環匯入（含函式內延遲匯入）。"""
import ast
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
from review_snapshot import rule_scopes

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

    def test_rule_scopes_come_from_master_catalog(self):
        scopes = rule_scopes()
        self.assertEqual(len(scopes), 70)
        self.assertEqual(sorted(set(scopes.values())), ["cross_file", "local", "project"])


if __name__ == "__main__":
    unittest.main()
