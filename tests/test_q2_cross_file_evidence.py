"""Q2：跨檔鏈證據與排除依據的正反回歸；不以合成通過代表真實專案審查。"""
from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from review_safety import CLOSURES, INDEX, SNAPSHOT, _write, closure_errors, report_dir
from cross_file_evidence import trace_errors


class CrossFileEvidenceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.paths = ["Controller.cs", "Handler.cs", "Service.cs", "Repository.cs"]
        bodies = [
            "public class Controller {\n public bool Get() => handler.Handle();\n}\n",
            "public class Handler {\n public bool Handle() => service.Run();\n}\n",
            "public class Service {\n public bool Run() => repository.Query();\n}\n",
            "public class Repository {\n public bool Query() => true;\n}\n",
        ]
        for path, body in zip(self.paths, bodies):
            (self.root / path).write_text(body, encoding="utf-8")
        (self.root / "Unrelated.cs").write_text(
            "public class Unrelated {\n public bool Execute() => true;\n}\n",
            encoding="utf-8")
        (self.root / "Another.cs").write_text(
            "public class Another {\n public bool Execute() => false;\n}\n",
            encoding="utf-8")
        self.report = report_dir(self.root)
        known = {p: "sha" for p in self.paths + ["Unrelated.cs", "Another.cs"]}
        self.snapshot = {"schema_version": 1, "source_hashes": known}
        self.edges = [
            {"id": f"edge-{i}", "kind": "method_call_hint", "source": origin,
             "target": dest, "line": 2, "callsite_id": f"call-{i}",
             "resolution": "candidate_only"}
            for i, (origin, dest) in enumerate(zip(self.paths, self.paths[1:]), 1)
        ]
        self.index = {
            "schema_version": 8,
            "cross_file_evidence_version": 1,
            "typed_relationships": self.edges,
            "rule_candidates": {"Controller.cs": [{"rule_id": "AC-08"}]},
            "cross_file_call_hints": {
                p: [{
                    "id": f"call-{i}", "called_method": method, "line": 2,
                    "possible_targets": [{"path": dest, "line": 2}],
                }]
                for i, (p, dest, method) in enumerate(zip(
                    self.paths, self.paths[1:], ["Handle", "Run", "Query"]), 1)
            },
        }
        self.check = {
            "id": "AC-08", "status": "pass",
            "evidence": [{"kind": "source", "path": "Service.cs",
                          "line_start": 2, "line_end": 2}],
            "execution": {"state": "completed", "inspected_paths": self.paths},
        }
        self.trace = {
            "boundary": "connected",
            "nodes": [
                {"role": role, "path": p, "line_start": 2, "line_end": 2,
                 "reason": f"已檢查 {p} 的實際分支、參數與控制責任，並追蹤相鄰呼叫點"}
                for role, p in zip(
                    ["entry", "support", "enforcement", "operation"], self.paths)
            ],
            "relationships": [
                {"relationship_id": edge["id"],
                 "reason": f"已核對 {edge['source']} 第 2 行呼叫與 {edge['target']} 的真實目標",
                 "evidence": {"path": edge["source"], "line_start": 2, "line_end": 2}}
                for edge in self.edges
            ],
        }
        self.closure = {
            "status": "pass",
            "summary": "已沿入口、Handler、Service 與 Repository 核對實際呼叫鏈及來源",
            "control_owner": "服務端授權與資料操作",
            "search_summary": "已搜尋直接 Endpoint、Handler、授權分支以及 Service 與 Repository 的旁路",
            "examined_paths": list(self.paths),
            "examined_relationship_ids": [e["id"] for e in self.edges],
            "callsite_reviews": {
                f"call-{i}": {
                    "status": "verified", "selected_targets": [dest],
                    "reason": f"已核對 {p} 真正呼叫 {method} 並抵達 {dest} 實作",
                    "binding": "direct",
                    "evidence": {"path": p, "line_start": 2, "line_end": 2},
                }
                for i, (p, dest, method) in enumerate(zip(
                    self.paths, self.paths[1:], ["Handle", "Run", "Query"]), 1)
            },
            "dismissed_relationships": {},
            "control_trace": self.trace,
            "open_issues": [],
        }
        self.save()

    def save(self):
        _write(self.report / SNAPSHOT, self.snapshot)
        _write(self.report / INDEX, self.index)
        _write(self.report / CLOSURES, {"AC-08": self.closure})

    def errors(self):
        self.save()
        return closure_errors(self.root, {"checks": [self.check]})

    def test_connected_controller_handler_service_repository_has_grounded_proofs(self):
        self.assertEqual(self.errors(), [])

    def test_missing_trace_cannot_close_rule_with_only_relationship_ids(self):
        self.closure.pop("control_trace")
        self.assertIn("缺少實際入口", "；".join(self.errors()))

    def test_forged_call_line_and_selected_target_are_rejected(self):
        self.closure["control_trace"]["relationships"][1]["evidence"]["line_start"] = 1
        self.closure["control_trace"]["relationships"][1]["evidence"]["line_end"] = 1
        self.assertIn("實際呼叫", "；".join(self.errors()))
        self.closure = copy.deepcopy(self.closure)
        self.closure["callsite_reviews"]["call-2"]["selected_targets"] = ["Unrelated.cs"]
        self.assertIn("目標必須來自", "；".join(self.errors()))

    def test_blanket_exclusion_cannot_claim_verified_chain(self):
        for row in self.closure["callsite_reviews"].values():
            row["status"] = "excluded"
            row["selected_targets"] = []
            row["exclusion_basis"] = "unrelated_rule"
        self.assertIn("Method 呼叫未有 verified", "；".join(self.errors()))

    def test_reviewed_every_file_must_not_expand_all_rule_candidates(self):
        self.closure["examined_paths"].extend(["Unrelated.cs", "Another.cs"])
        self.check["execution"]["inspected_paths"].extend(["Unrelated.cs", "Another.cs"])
        self.index["typed_relationships"].append({
            "id": "unrelated-edge", "kind": "method_call_hint",
            "source": "Unrelated.cs", "target": "Another.cs", "line": 2,
            "resolution": "candidate_only"
        })
        self.assertEqual(self.errors(), [])

    def test_excluded_edge_requires_grounded_source_not_generic_sentence(self):
        self.index["typed_relationships"].append({
            "id": "candidate-exclude", "kind": "di_registration",
            "source": "Controller.cs", "target": "Unrelated.cs", "line": 2,
            "resolution": "candidate_only"
        })
        self.closure["dismissed_relationships"]["candidate-exclude"] = (
            "這個候選可能屬於其他元件故不需要查核來源，只列入已排除")
        self.assertIn("必須附具體分類及來源證據", "；".join(self.errors()))
        self.closure["dismissed_relationships"]["candidate-exclude"] = {
            "basis": "unrelated_rule",
            "reason": "Controller.cs 的此註冊候選與 AC-08 的物件層級授權無關，已核對呼叫分支",
            "evidence": {"path": "Controller.cs", "line_start": 2, "line_end": 2},
        }
        self.assertEqual(self.errors(), [])

    def test_unconnected_or_unverified_nodes_cannot_complete_connected_chain(self):
        self.closure["control_trace"]["relationships"] = [
            self.closure["control_trace"]["relationships"][0]]
        self.closure["examined_relationship_ids"] = ["edge-1"]
        self.closure["dismissed_relationships"] = {
            "edge-2": {"basis": "unrelated_rule", "reason": "已查閱 Handler 並確認不同的實際控制責任",
                       "evidence": {"path": "Handler.cs", "line_start": 2, "line_end": 2}},
            "edge-3": {"basis": "unrelated_rule", "reason": "已查閱 Service 並確認不同的實際控制責任",
                       "evidence": {"path": "Service.cs", "line_start": 2, "line_end": 2}},
        }
        self.assertIn("未形成可追溯", "；".join(self.errors()))

    def test_single_file_control_is_allowed_with_actual_reason(self):
        self.index["typed_relationships"] = []
        self.index["cross_file_call_hints"] = {}
        self.closure["examined_paths"] = ["Service.cs"]
        self.closure["examined_relationship_ids"] = []
        self.closure["callsite_reviews"] = {}
        self.closure["control_trace"] = {
            "boundary": "single_file",
            "boundary_reason": "已搜尋來源、控制執行與受保護資料存取，確認本案實際控制責任只位於 Service.cs",
            "nodes": [self.trace["nodes"][2]],
            "relationships": [],
        }
        self.assertEqual(self.errors(), [])

    def test_old_index_does_not_reinterpret_existing_review(self):
        self.index.pop("cross_file_evidence_version")
        self.closure.pop("control_trace")
        self.assertEqual(self.errors(), [])


if __name__ == "__main__":
    unittest.main()
