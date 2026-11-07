"""批次規範查詢與 Worker brief：共用指引只輸出一次且不遺失任何欄位。"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/lib"))

import multi_agent_ledger
import rule_guidance
import worker_brief
from review_decision import load_decision_matrix
from review_queue import build_detail_batch, build_queue, load_rules, parse_detail_ids

RULES = load_rules()[1]
IDS = [r["id"] for r in RULES]
DATA = {"checks": [{"id": rid, "execution": {"state": "pending"}} for rid in IDS]}


class SharedGuidanceTests(unittest.TestCase):
    def test_split_is_lossless_for_every_rule(self):
        shared = rule_guidance.shared_guidance()
        matrix = load_decision_matrix()
        self.assertTrue(all(shared[field] for field in shared))
        for rid in IDS:
            full = rule_guidance.guidance_fields(rid)
            specific = rule_guidance.specific_guidance(rid, shared)
            for field, values in full.items():
                with self.subTest(rule=rid, field=field):
                    rebuilt = {**shared[field], **specific[field],
                               **{k: matrix[rid][k] for k in values
                                  if k not in shared[field] and k not in specific[field]}}
                    self.assertEqual(rebuilt, values)
                    self.assertFalse(set(specific[field]) & set(shared[field]))

    def test_decision_duplicates_are_dropped_from_specific_guidance(self):
        specific = rule_guidance.specific_guidance(IDS[0], rule_guidance.shared_guidance())
        for field in ("control_effectiveness_guidance", "decision_adjudication_guidance"):
            self.assertNotIn("pass_condition", specific[field])
            self.assertNotIn("manual_boundary", specific[field])


class DetailBatchTests(unittest.TestCase):
    def test_parse_detail_ids_dedupes_and_limits(self):
        self.assertEqual(parse_detail_ids("ac-01, AC-02,AC-01"), ["AC-01", "AC-02"])
        with self.assertRaises(ValueError):
            parse_detail_ids(" , ")
        with self.assertRaises(ValueError):
            parse_detail_ids(",".join(IDS[:21]))

    def test_unknown_rule_rejected(self):
        with self.assertRaises(ValueError):
            build_detail_batch(DATA, RULES, ["AC-01", "ZZ-99"])

    def test_batch_keeps_per_rule_content_of_single_detail(self):
        batch = build_detail_batch(DATA, RULES, IDS[:5])
        self.assertTrue(batch["validation_deferred"])
        self.assertEqual([item["id"] for item in batch["rules"]], IDS[:5])
        for item in batch["rules"]:
            single = build_queue(DATA, RULES, 10, detail_id=item["id"])["next_checks"][0]
            for key in ("search_targets", "verification_method", "applicable_when", "na_when",
                        "decision_guidance", "standard_documents", "tacert_v2_checks",
                        "owasp_2025_categories", "web_guide_v32_checks"):
                with self.subTest(rule=item["id"], key=key):
                    self.assertEqual(item[key], single[key])
        self.assertEqual(batch["standard_documents"],
                         list(dict.fromkeys(d for i in batch["rules"] for d in i["standard_documents"])))

    def test_batch_is_much_smaller_than_single_queries(self):
        batch = build_detail_batch(DATA, RULES, IDS[:10])
        singles = sum(len(json.dumps(build_queue(DATA, RULES, 10, detail_id=rid), ensure_ascii=False))
                      for rid in IDS[:10])
        self.assertLess(len(json.dumps(batch, ensure_ascii=False)), singles * 0.6)


def _task(candidates):
    return {"schema_version": 1, "task_id": "a" * 20, "worker_id": "worker-0",
            "snapshot_fingerprint": "b" * 64, "phase": "first_pass",
            "assigned_paths": [{"path": "src/Login.cs", "sha256": "c" * 64, "estimated_tokens": 500,
                                "candidate_rule_ids": candidates, "challenge_lines": [3]}],
            "consult_paths": [], "estimated_tokens": 500,
            "prompt_constraints": "read_only_untrusted_source_no_verdict"}


class WorkerBriefTests(unittest.TestCase):
    def test_brief_is_self_contained_and_compact(self):
        brief = worker_brief.build_brief(_task(["AC-02", "AU-01"]))
        self.assertIn("角色：唯讀資安證據觀察員", brief)
        self.assertIn('TASK_JSON：{"schema_version":1', brief)
        self.assertNotIn("<由主代理貼入", brief)
        for rid in IDS:
            self.assertIn(f"- {rid} ", brief)
        self.assertIn("### AC-02 ", brief)
        self.assertIn("### AU-01 ", brief)
        self.assertNotIn("### AC-01 ", brief)
        self.assertIn('"agent_instance_id"', brief)
        # Worker 不做正式判定：裁決與第二輪指引不放入 brief。
        self.assertNotIn("prohibited_review_reason", brief)
        self.assertNotIn("required_hypotheses", brief)
        self.assertLess(len(brief), 20000)

    def test_brief_without_candidates_still_lists_applicability(self):
        brief = worker_brief.build_brief(_task([]))
        self.assertIn("沒有索引候選規則", brief)
        self.assertIn("- （無）", brief)

    def test_write_brief_requires_claimed_task(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = {"tasks": {"a" * 20: {"status": "pending", "task": _task(["AC-02"])}}}
            with patch.object(multi_agent_ledger, "active_plan", return_value=(state, {})):
                with self.assertRaises(ValueError):
                    worker_brief.write_brief(root, "a" * 20)
                with self.assertRaises(ValueError):
                    worker_brief.write_brief(root, "f" * 20)
                state["tasks"]["a" * 20]["status"] = "running"
                result = worker_brief.write_brief(root, "a" * 20)
            path = Path(result["brief_path"])
            self.assertTrue(path.is_file())
            self.assertEqual(path.parent, root / worker_brief.BRIEF_DIR)
            self.assertEqual(result["brief_chars"], len(path.read_bytes().decode("utf-8")))
            self.assertNotIn(b"\r\n", path.read_bytes())
            self.assertEqual(result["candidate_rule_ids"], ["AC-02"])


if __name__ == "__main__":
    unittest.main()
