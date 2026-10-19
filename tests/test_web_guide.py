"""V3.2 Web 技術指引與既有 70 項關聯；排除 Java/PHP 技術實作。"""
import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from web_guide import load_web_guide, web_guide_review_hints, build_web_guide_index, validate_web_guide_index


class NicsWebGuideV32Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = json.loads((ROOT / "rules.json").read_text(encoding="utf-8"))["rules"]

    def test_official_chapter4_category_and_topic_counts(self):
        doc = load_web_guide(self.rules)
        self.assertEqual(doc["version"], "V3.2")
        self.assertEqual(len(doc["controls"]), 29)
        topics = [t for c in doc["controls"] for t in c["implementation_topics"]]
        self.assertEqual(len(topics), 35)
        self.assertTrue(all(t["observed_levels"] and t["levels_evidence"] for t in topics))
        self.assertEqual(len({t["source_section"] for t in topics}), 35)
        counts = {area: sum(c["source_section"].startswith(area + ".") for c in doc["controls"])
                  for area in ("4.1", "4.2", "4.3", "4.4", "4.5", "4.6", "4.7")}
        self.assertEqual(counts, {"4.1": 3, "4.2": 6, "4.3": 2, "4.4": 5,
                                  "4.5": 8, "4.6": 2, "4.7": 3})

    def test_scope_excludes_language_specific_java_php(self):
        doc = load_web_guide(self.rules)
        self.assertEqual(doc["scope"]["excluded_implementation_technologies"], ["Java", "PHP"])
        self.assertEqual(doc["owasp_reference_in_document"], "OWASP Top 10:2021")
        for cat in doc["controls"]:
            self.assertNotIn("jsp", cat["review_focus"].lower())
            self.assertNotIn("servlet", cat["review_focus"].lower())
            self.assertNotIn("php", cat["review_focus"].lower())
            for topic in cat["implementation_topics"]:
                self.assertNotIn("jsp", topic["review_focus"].lower())
                self.assertNotIn("servlet", topic["review_focus"].lower())
                self.assertNotIn("php", topic["review_focus"].lower())

    def test_http_headers_mapping_not_naive_copy_of_pdf_example(self):
        doc = load_web_guide(self.rules)
        cat = next(c for c in doc["controls"] if c["source_section"] == "4.5.3")
        entry = next(t for t in cat["implementation_topics"] if t["source_section"] == "4.5.3.4")
        self.assertEqual(entry["pdf_page"], 207)
        self.assertEqual(entry["observed_levels"], ["中", "高"])
        self.assertIn("CR-05", entry["related_rule_ids"])
        self.assertIn("unsafe-inline", entry["review_focus"])
        self.assertIn("unsafe-eval", entry["review_focus"])
        self.assertIn("CSP", entry["review_focus"])

    def test_mapping_and_report_are_guidance_not_compliance(self):
        hints = web_guide_review_hints(self.rules)
        self.assertEqual(set(hints), {r["id"] for r in self.rules})
        all_categories = {c["id"] for group in hints.values() for c in group}
        self.assertEqual(len(all_categories), 29)
        self.assertIn("NICS-WEB-4.5.3", [c["id"] for c in hints["CR-05"]])
        self.assertTrue(all("status" not in c for group in hints.values() for c in group))
        report = build_web_guide_index(self.rules)
        self.assertEqual(report["category_count"], 29)
        self.assertEqual(report["implementation_topic_count"], 35)
        self.assertNotIn("status", report["controls"][0])
        self.assertEqual(validate_web_guide_index(self.rules, report), [])
        altered = copy.deepcopy(report)
        altered["scope"]["excluded_implementation_technologies"] = []
        self.assertTrue(validate_web_guide_index(self.rules, altered))


if __name__ == "__main__":
    unittest.main()
