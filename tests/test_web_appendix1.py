"""V3.2 附件1 55 項表格、分級及人工佐證隔離測試。"""
from __future__ import annotations
import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/lib"))
from web_appendix1 import (
    load_appendix1, appendix_review_hints, build_appendix1,
    validate_appendix1, review_from_report,
)


class WebAppendix1Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = json.loads((ROOT / "rules.json").read_text(encoding="utf-8"))["rules"]

    def test_exact_counts_and_chapter_crosswalk(self):
        guide = load_appendix1(self.rules)
        entries = guide["checks"]
        self.assertEqual(len(entries), 55)
        self.assertEqual(len({c["id"] for c in entries}), 55)
        self.assertEqual(len({c["parent_section"] for c in entries}), 27)
        self.assertEqual([sum(l in c["applicable_levels"] for c in entries)
                          for l in ("普", "中", "高")], [33, 44, 55])
        self.assertTrue(all(1 <= c["pdf_page"] <= 5 for c in entries))
        self.assertNotIn("4.5.3.4", {c["parent_section"] for c in entries})
        self.assertEqual(guide["scope"]["excluded_implementation_technologies"], ["Java", "PHP"])
        self.assertEqual(entries[0]["related_rule_ids"], ["AC-01"])
        self.assertEqual(entries[-1]["related_rule_ids"], ["IN-05"])

    def test_source_guidance_and_no_generated_compliance(self):
        mapped = appendix_review_hints(self.rules)
        self.assertEqual(set(mapped), {rule["id"] for rule in self.rules})
        self.assertEqual({c["id"] for values in mapped.values() for c in values},
                         {f"NICS-WEB-A1-{n:03d}" for n in range(1, 56)})
        self.assertTrue(any(x["id"] == "NICS-WEB-A1-001" for x in mapped["AC-01"]))
        self.assertTrue(all("status" not in e for rows in mapped.values() for e in rows))

    def test_unclassified_remains_55_pending(self):
        report = build_appendix1({"security_level": "A"}, self.rules)
        self.assertEqual(report["demand_level"], "待確認")
        self.assertIsNone(report["applicable_items"])
        self.assertEqual(report["status_counts"], {"pending_level": 55})
        self.assertEqual(validate_appendix1({"security_level": "A"}, self.rules, report), [])

    def test_demand_level_applicability_independent_from_A_to_E(self):
        for level, count in (("普", 33), ("中", 44), ("高", 55)):
            project = {"protection_demand_level": level,
                       "protection_demand_level_basis": "已核實系統防護需求分級"}
            output = build_appendix1(project, self.rules)
            self.assertEqual(output["applicable_items"], count)
            self.assertEqual(output["status_counts"].get("not_assessed", 0), count)
            self.assertEqual(output["status_counts"].get("not_applicable_by_level", 0), 55-count)
        with self.assertRaises(ValueError):
            build_appendix1({"protection_demand_level": "中"}, self.rules)

    def test_no_pass_without_real_evidence_and_review_roundtrip(self):
        project = {"protection_demand_level": "普", "protection_demand_level_basis": "核定紀錄"}
        entry = {"id": "NICS-WEB-A1-001", "status": "pass",
                 "reason": "已核對伺服器 Session 逾時邏輯",
                 "reviewer": "審查人員", "verified_on": "2026-10-20",
                 "evidence": ["src/Auth.cs:38-56"]}
        result = build_appendix1(project, self.rules, {"checks": [entry]})
        self.assertEqual(result["status_counts"]["pass"], 1)
        self.assertEqual(result["status_counts"]["not_assessed"], 32)
        self.assertEqual(review_from_report(result), {"checks": [entry]})
        self.assertEqual(validate_appendix1(project, self.rules, result), [])
        bad = copy.deepcopy(entry)
        bad["evidence"] = []
        with self.assertRaises(ValueError):
            build_appendix1(project, self.rules, {"checks": [bad]})
        high_only = copy.deepcopy(entry)
        high_only["id"] = "NICS-WEB-A1-013"  # 稽核失效告警，僅高級
        with self.assertRaises(ValueError):
            build_appendix1(project, self.rules, {"checks": [high_only]})
        with self.assertRaises(ValueError):
            build_appendix1({}, self.rules, {"checks": [entry]})

    def test_review_requires_authorship_and_tampering_rejected(self):
        project = {"protection_demand_level": "中", "protection_demand_level_basis": "核定資料"}
        record = {"id": "NICS-WEB-A1-023", "status": "review",
                  "reason": "仍待確認實際密碼政策", "reviewer": "審查人員",
                  "verified_on": "2026-10-20", "evidence": []}
        result = build_appendix1(project, self.rules, {"checks": [record]})
        self.assertEqual(result["status_counts"]["review"], 1)
        self.assertEqual(result["status_counts"].get("pass", 0), 0)
        forged = copy.deepcopy(result)
        forged["status_counts"]["pass"] = 33
        self.assertTrue(validate_appendix1(project, self.rules, forged))
        forged2 = copy.deepcopy(result)
        forged2["checks"][0]["status"] = "pass"
        self.assertTrue(validate_appendix1(project, self.rules, forged2))


if __name__ == "__main__":
    unittest.main()
