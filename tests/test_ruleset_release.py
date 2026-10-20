"""規則集正式版 v2.0.0 與既有 v2.0.0-rc1 審查進度相容性。"""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from report_common import validate_data
from review_queue import load_rules

CATEGORIES = ("AC", "AU", "IN", "CR", "EH", "LG", "DP", "PD", "BC", "SI")


class StableRulesetReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ruleset = json.loads((ROOT / "rules.json").read_text(encoding="utf-8"))
        cls.yaml_ruleset = yaml.safe_load((ROOT / "rules.yaml").read_text(encoding="utf-8"))

    def test_stable_release_is_consistent_across_70_rules(self):
        self.assertEqual(self.ruleset["ruleset_version"], "2.0.0")
        self.assertEqual(self.ruleset["release_status"], "stable")
        self.assertEqual(self.ruleset["release_date"], "2026-10-20")
        self.assertEqual(len(self.ruleset["rules"]), 70)
        self.assertEqual(len({r["id"] for r in self.ruleset["rules"]}), 70)
        self.assertTrue(all(r["rule_version"] == "2.0.0" for r in self.ruleset["rules"]))
        self.assertEqual(self.ruleset, self.yaml_ruleset)
        for prefix in CATEGORIES:
            document = yaml.safe_load((ROOT / "rules" / f"{prefix}.yaml").read_text(encoding="utf-8"))
            self.assertEqual(document["ruleset_version"], "2.0.0")
            self.assertEqual(document["rules"], [
                r for r in self.ruleset["rules"] if r["category"] == prefix
            ])

    def test_new_queue_has_stable_ruleset_version(self):
        metadata, rules = load_rules()
        self.assertEqual(metadata["ruleset_version"], "2.0.0")
        self.assertEqual(len(rules), 70)

    def test_stable_rules_schema(self):
        schema = json.loads((ROOT / "schemas/rules.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(list(Draft202012Validator(schema).iter_errors(self.ruleset)), [])
        self.assertEqual(schema["properties"]["release_status"]["const"], "stable")

    def test_legacy_assessment_remains_schema_valid(self):
        schema = json.loads((ROOT / "schemas/assessment.schema.json").read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        assessment = json.loads((ROOT / "examples/assessment.example.json").read_text(encoding="utf-8"))
        self.assertEqual(assessment["ruleset_version"], "2.0.0")
        self.assertEqual(list(validator.iter_errors(assessment)), [])
        old = copy.deepcopy(assessment)
        old["ruleset_version"] = "2.0.0-rc1"
        self.assertEqual(list(validator.iter_errors(old)), [])
        future = copy.deepcopy(assessment)
        future["ruleset_version"] = "3.0.0"
        self.assertTrue(list(validator.iter_errors(future)))

    def test_legacy_report_keeps_findings_and_warns_not_fails_version(self):
        payload = json.loads((ROOT / "examples/report-data.example.json").read_text(encoding="utf-8"))
        payload["assessment"]["ruleset_version"] = "2.0.0-rc1"
        findings = copy.deepcopy(payload["assessment"]["findings"])
        result = validate_data(payload, allow_demo=True)
        self.assertFalse(any("ruleset_version" in message for message in result.errors), result.errors)
        self.assertTrue(any("2.0.0-rc1" in message for message in result.warnings),
                        result.warnings)
        self.assertEqual(payload["assessment"]["findings"], findings)


if __name__ == "__main__":
    unittest.main()
