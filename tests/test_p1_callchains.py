"""P1 單代理跨檔鏈追查：符號候選、無截斷、未處理候選不得結案。"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/lib"))
from analysis_adapters import probe_roslyn
from analysis_prepare import cross_file_call_hints, prepare
from review_relationships import build_relationships
from review_safety import _write
from review_snapshot import CLOSURES, INDEX, SNAPSHOT, closure_errors, report_dir


class P1CallchainTests(unittest.TestCase):
    def test_more_than_8_overloads_and_200_callsites_are_never_silently_dropped(self):
        indexed = {
            "Controller.cs": {
                "methods": [{"name": "Get", "line": 1}],
                "calls": [
                    {"called_method": "Handle", "containing_method": "Get",
                     "line": i + 1, "argument_count": 1, "receiver": "_handler"}
                    for i in range(250)
                ],
            },
            **{
                f"Handler{i}.cs": {"methods": [
                    {"name": "Handle", "line": i + 1,
                     "containing_type": f"Handler{i}", "parameter_count": 1}
                ], "calls": []}
                for i in range(12)
            },
        }
        calls = cross_file_call_hints(indexed)["Controller.cs"]
        self.assertEqual(len(calls), 250)
        self.assertEqual(len({c["id"] for c in calls}), 250)
        self.assertEqual({c["candidate_count"] for c in calls}, {12})
        self.assertEqual(len(calls[0]["possible_targets"]), 12)
        self.assertTrue(all(c["requires_manual_verification"] for c in calls))

    def test_receiver_type_filters_same_named_unrelated_methods(self):
        indexed = {
            "Caller.cs": {"methods": [], "calls": [
                {"called_method": "Handle", "receiver": "_handler",
                 "receiver_type": "App.Orders.OrderHandler",
                 "containing_method": "Fetch", "line": 8, "argument_count": 1},
            ]},
            "OrderHandler.cs": {"methods": [{"name": "Handle", "line": 3,
                                            "containing_type": "OrderHandler",
                                            "parameter_count": 1}], "calls": []},
            "LoginHandler.cs": {"methods": [{"name": "Handle", "line": 3,
                                            "containing_type": "LoginHandler",
                                            "parameter_count": 1}], "calls": []},
        }
        result = cross_file_call_hints(indexed)["Caller.cs"][0]
        self.assertEqual(result["resolution"], "receiver_type_candidate")
        self.assertEqual([x["path"] for x in result["possible_targets"]], ["OrderHandler.cs"])
        self.assertTrue(result["requires_manual_verification"])

    def test_semantic_candidate_target_is_preferred_but_not_declared_verified(self):
        indexed = {
            "Controller.cs": {"methods": [], "calls": [{
                "called_method": "Handle", "line": 12, "argument_count": 1,
                "semantic_state": "symbol_candidate",
                "semantic_targets": [{"path": "OrderHandler.cs", "method": "Handle", "line": 7}],
            }]},
            "OrderHandler.cs": {"methods": [{"name": "Handle", "line": 7}], "calls": []},
            "OtherHandler.cs": {"methods": [{"name": "Handle", "line": 7}], "calls": []},
        }
        call = cross_file_call_hints(indexed)["Controller.cs"][0]
        self.assertEqual(call["resolution"], "semantic_symbol_candidate")
        self.assertEqual(call["possible_targets"][0]["path"], "OrderHandler.cs")
        self.assertEqual(call["candidate_count"], 1)
        self.assertTrue(call["requires_manual_verification"])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for path in indexed:
                (root / path).write_text("public class Placeholder {}\n", encoding="utf-8")
            edges = build_relationships(root, list(indexed), {"Controller.cs": [call]})
            method_edges = [edge for edge in edges if edge["kind"] == "method_call_hint"]
            self.assertEqual(len(method_edges), 1)
            self.assertEqual(method_edges[0]["callsite_id"], call["id"])
            self.assertEqual(method_edges[0]["resolution"], "candidate_only")

    def test_same_line_duplicate_invocations_get_distinct_ids(self):
        indexed = {
            "Caller.cs": {"methods": [], "calls": [
                {"called_method": "Go", "line": 4, "argument_count": 0},
                {"called_method": "Go", "line": 4, "argument_count": 0}
            ]},
            "Target.cs": {"methods": [{"name": "Go", "line": 5}], "calls": []}
        }
        hints = cross_file_call_hints(indexed)["Caller.cs"]
        self.assertEqual(len(hints), 2)
        self.assertNotEqual(hints[0]["id"], hints[1]["id"])

    def test_local_symbol_does_not_invent_unrelated_cross_file_call(self):
        indexed = {
            "Caller.cs": {"methods": [{"name": "Run", "line": 1}],
                          "calls": [{
                              "called_method": "Run", "line": 6, "argument_count": 0,
                              "semantic_state": "symbol_candidate",
                              "semantic_targets": [{"path": "Caller.cs", "line": 1,
                                                     "method": "Run"}]
                          }]},
            "Unrelated.cs": {"methods": [{"name": "Run", "line": 4}], "calls": []},
        }
        self.assertEqual(cross_file_call_hints(indexed), {})

    def test_dispatch_without_local_implementation_stays_unresolved(self):
        indexed = {
            "Caller.cs": {"methods": [], "calls": [{
                "called_method": "Authorize", "line": 4, "argument_count": 1,
                "semantic_state": "dispatch_candidate",
                "semantic_targets": [{"path": "Caller.cs", "method": "Authorize", "line": 1}]
            }]},
            "Unrelated.cs": {"methods": [], "calls": []},
        }
        call = cross_file_call_hints(indexed)["Caller.cs"][0]
        self.assertEqual(call["resolution"], "dispatch_requires_manual_search")
        self.assertEqual(call["possible_targets"], [])
        self.assertTrue(call["requires_manual_verification"])

    def test_unresolved_callsite_blocks_closure_until_manual_review(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            report = report_dir(root)
            call = {
                "id": "test-callsite-1", "called_method": "Handle",
                "possible_targets": [{"path": "Target.cs", "line": 2}],
                "resolution": "name_only_ambiguous"
            }
            _write(report / SNAPSHOT, {"schema_version": 1,
                   "source_hashes": {"Caller.cs": "a", "Target.cs": "b"}})
            _write(report / INDEX, {
                "schema_version": 3,
                "typed_relationships": [],
                "rule_candidates": {"Caller.cs": [{"rule_id": "AC-08"}]},
                "cross_file_call_hints": {"Caller.cs": [call]},
            })
            checks = [{"id": "AC-08", "status": "pass",
                       "execution": {"state": "completed"}}]
            closure = {
                "status": "pass",
                "summary": "已核對入口與授權來源及所有呼叫端條件與實際資料存取限制",
                "control_owner": "授權控制元件",
                "search_summary": "已跨檔查核授權處理與服務內部資料查詢及其它呼叫入口",
                "examined_paths": ["Caller.cs", "Target.cs"],
                "examined_relationship_ids": [],
                "open_issues": [],
            }
            _write(report / CLOSURES, {"AC-08": closure})
            errors = closure_errors(root, {"checks": checks})
            self.assertTrue(any("尚未由 Agent 核對" in e for e in errors), errors)
            closure["callsite_reviews"] = {"test-callsite-1": {
                "status": "verified", "reason": "已核對呼叫端傳入的型別、方法宣告與注入服務實作",
                "selected_targets": ["Unrelated.cs"]
            }}
            _write(report / CLOSURES, {"AC-08": closure})
            self.assertTrue(any("目標必須來自" in e for e in closure_errors(root, {"checks": checks})))
            closure["callsite_reviews"]["test-callsite-1"]["selected_targets"] = ["Target.cs"]
            _write(report / CLOSURES, {"AC-08": closure})
            self.assertEqual(closure_errors(root, {"checks": checks}), [])
            closure["callsite_reviews"]["test-callsite-1"]["status"] = "unresolved"
            _write(report / CLOSURES, {"AC-08": closure})
            self.assertTrue(any("verified/excluded" in e for e in closure_errors(root, {"checks": checks})))

    def test_incremental_change_invalidates_unmodified_callsite_symbols(self):
        from review_safety import refresh_snapshot
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Case.csproj").write_text(
                '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
                '<TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>',
                encoding="utf-8")
            (root / "Caller.cs").write_text(
                "public class Caller { public void Go() => new Target().Run(); }",
                encoding="utf-8")
            (root / "Target.cs").write_text(
                "public class Target { public void Run() {} }",
                encoding="utf-8")
            pending_runs = []
            def fake_roslyn(source_root, pending, probe):
                pending_runs.append(sorted(pending))
                return ({p: {"methods": [], "calls": [], "types": []} for p in pending}, [])
            with (patch("analysis_prepare.probe_roslyn", return_value={"available": True, "sdk_version": "8.0"}),
                  patch("analysis_prepare.probe_codegraph", return_value={"available": False}),
                  patch("analysis_prepare.run_roslyn", side_effect=fake_roslyn)):
                prepare(root, "full")
                unchanged = prepare(root, "incremental")
                self.assertEqual(unchanged["roslyn_reused_count"], 2)
                self.assertEqual(len(pending_runs), 2)  # 第二輪有快取，不會重新索引
                self.assertEqual(pending_runs[-1], [])
                (root / "Target.cs").write_text(
                    "public class Target { public void Run(int value) {} }",
                    encoding="utf-8")
                refresh_snapshot(root)
                result = prepare(root, "incremental")
                self.assertEqual(pending_runs[-1], ["Caller.cs", "Target.cs"])
                self.assertEqual(result["roslyn_reused_count"], 0)

    def test_roslyn_keeps_interface_and_virtual_runtime_dispatch_candidates(self):
        if not probe_roslyn()["available"]:
            self.skipTest("dotnet SDK 8+ unavailable")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Case.csproj").write_text(
                '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
                '<TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>',
                encoding="utf-8")
            sources = {
                "IGuard.cs": "public interface IGuard { bool Check(); }\n",
                "GuardA.cs": "public sealed class GuardA : IGuard { public bool Check() => true; }\n",
                "GuardB.cs": "public sealed class GuardB : IGuard { public bool Check() => false; }\n",
                "Base.cs": "public class Base { public virtual bool Check() => true; }\n",
                "Override.cs": "public sealed class Override : Base { public override bool Check() => false; }\n",
                "Caller.cs": (
                    "public sealed class Caller {\n"
                    " public bool Guard(IGuard x) => x.Check();\n"
                    " public bool Virtual(Base x) => x.Check();\n"
                    "}\n"
                ),
            }
            for name, content in sources.items():
                (root / name).write_text(content, encoding="utf-8")
            with patch("analysis_prepare.probe_codegraph", return_value={"available": False}):
                result = prepare(root)
            self.assertFalse(result["roslyn_errors"], result["roslyn_errors"])
            index = json.loads((root / "reports/security-code-review/analysis/structure-index.json")
                               .read_text("utf-8"))
            calls = index["cross_file_call_hints"]["Caller.cs"]
            by_caller = {call["caller_method"]: call for call in calls}
            self.assertEqual(by_caller["Guard"]["resolution"], "semantic_dispatch_candidate")
            self.assertEqual(
                {x["path"] for x in by_caller["Guard"]["possible_targets"]},
                {"IGuard.cs", "GuardA.cs", "GuardB.cs"}
            )
            self.assertEqual(by_caller["Virtual"]["resolution"], "semantic_dispatch_candidate")
            self.assertEqual(
                {x["path"] for x in by_caller["Virtual"]["possible_targets"]},
                {"Base.cs", "Override.cs"}
            )

    def test_roslyn_traces_real_p0_controller_handler_service_repository(self):
        if not probe_roslyn()["available"]:
            self.skipTest("dotnet SDK 8+ unavailable")
        from quality_baseline import load_catalog, PROJECT_FILE
        case = next(c for c in load_catalog()["cases"] if c["id"] == "idor-owner-checked")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Case.csproj").write_text(PROJECT_FILE, encoding="utf-8")
            for name, content in case["files"].items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            with patch("analysis_prepare.probe_codegraph", return_value={"available": False}):
                summary = prepare(root)
            self.assertFalse(summary["roslyn_errors"], summary["roslyn_errors"])
            index = json.loads((root / "reports/security-code-review/analysis/structure-index.json")
                               .read_text("utf-8"))
            hints = index["cross_file_call_hints"]
            expected = [
                ("OrderController.cs", "OrderHandler.cs"),
                ("OrderHandler.cs", "OrderService.cs"),
                ("OrderService.cs", "OrderRepository.cs"),
            ]
            for source, target in expected:
                with self.subTest(source=source, target=target):
                    self.assertIn(source, hints)
                    self.assertTrue(any(
                        item["resolution"].startswith("semantic_")
                        and any(t["path"] == target for t in item["possible_targets"])
                        for item in hints[source]
                    ), hints[source])
            self.assertTrue(all(
                edge["resolution"] == "candidate_only"
                for edge in index["typed_relationships"] if edge["kind"] == "method_call_hint"
            ))


if __name__ == "__main__":
    unittest.main()
