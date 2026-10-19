"""測試待辦佇列只協助工作排程，不假冒已執行審查。"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from review_queue import build_queue, load_rules

class ReviewQueueTests(unittest.TestCase):
    def test_pending_queue_uses_real_rule_targets(self):
        _, rules = load_rules()
        demo = json.loads((ROOT / "examples/assessment.example.json").read_text("utf-8"))
        demo["findings"] = [{"id": "F-01"}]
        output = build_queue(demo, rules, 10)
        self.assertEqual(output["pending"], 70)
        self.assertEqual(output["completed"], 0)
        self.assertEqual(output["findings_saved"], 1)
        self.assertFalse(output["ready_for_report"])
        self.assertEqual([x["id"] for x in output["next_checks"]],
                         [rule["id"] for rule in rules[:10]])
        self.assertTrue(output["next_checks"][0]["search_targets"])
        self.assertEqual(output["tacert_v2_supplemental_items"], 39)
        self.assertEqual(output["owasp_top10_2025_categories"], 10)
        self.assertTrue(any(v["owasp_2025_categories"] for v in output["next_checks"]))
        self.assertTrue(any(x["tacert_v2_checks"] for x in output["next_checks"]))

    def test_tacert_v2_mappings_have_source_and_external_checks(self):
        _, rules = load_rules()
        from review_queue import load_tacert_v2_checks
        mapped = load_tacert_v2_checks(rules)
        all_checks = {item["id"]: item for items in mapped.values() for item in items}
        self.assertEqual(len(all_checks), 39)
        self.assertEqual(all_checks["TACERT-V2-D01"]["pdf_page"], 6)
        self.assertEqual(all_checks["TACERT-V2-P10"]["verification_mode"], "hybrid")
        self.assertEqual(all_checks["TACERT-V2-R04"]["verification_mode"], "source")

    def test_owasp_2025_mapping_and_ssrf(self):
        from review_queue import load_owasp_2025_categories
        _, rules = load_rules()
        mapping = load_owasp_2025_categories(rules)
        ids = {item["id"] for per_rule in mapping.values() for item in per_rule}
        self.assertEqual(ids, {f"A{i:02d}:2025" for i in range(1, 11)})
        self.assertIn("A01:2025", [item["id"] for item in mapping["IN-08"]])
        self.assertNotIn("A10:2025", [item["id"] for item in mapping["IN-08"]])
        self.assertIn("A03:2025", [item["id"] for item in mapping["SI-01"]])
        self.assertIn("A10:2025", [item["id"] for item in mapping["EH-02"]])

    def test_only_remaining_checks_are_scheduled(self):
        _, rules = load_rules()
        demo = json.loads((ROOT / "examples/assessment.example.json").read_text("utf-8"))
        for check in demo["checks"][:10]:
            check["execution"]["state"] = "completed"
        out = build_queue(demo, rules, 5)
        self.assertEqual(out["completed"], 10)
        self.assertEqual(out["pending"], 60)
        self.assertEqual(out["next_checks"][0]["id"], rules[10]["id"])
        for check in demo["checks"][10:]:
            check["execution"]["state"] = "completed"
        out = build_queue(demo, rules, 10)
        self.assertTrue(out["ready_for_report"])
        self.assertEqual(out["next_checks"], [])

    def test_init_is_non_destructive(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "target"
            target.mkdir()
            cmd = [sys.executable, str(ROOT / "scripts/review_queue.py"),
                   "--target", str(target), "--init", "--batch-size", "3"]
            first = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
            self.assertEqual(first.returncode, 0, first.stderr)
            out = target / "reports/security-code-review/assessment.json"
            data = json.loads(out.read_text("utf-8"))
            self.assertEqual(len(data["checks"]), 70)
            data["findings"] = [{"id": "F-01"}]
            out.write_text(json.dumps(data, ensure_ascii=False), "utf-8")
            second = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(json.loads(out.read_text("utf-8"))["findings"][0]["id"], "F-01")

    def test_duplicate_and_missing_checks_rejected(self):
        _, rules = load_rules()
        demo = json.loads((ROOT / "examples/assessment.example.json").read_text("utf-8"))
        demo["checks"].pop()
        with self.assertRaises(ValueError):
            build_queue(demo, rules, 10)

if __name__ == "__main__":
    unittest.main()
