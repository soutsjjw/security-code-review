"""V3.2 附件3 六項安全標頭：.NET 對照、HTTP 實測與防假造狀態。"""
import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/lib"))
from web_headers import (
    HEADERS, load_headers, header_review_hints,
    build_appendix3, validate_appendix3, review_from_report,
)


class WebHeadersTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = json.loads((ROOT / "rules.json").read_text(encoding="utf-8"))["rules"]

    def test_six_source_headers_and_scope(self):
        doc = load_headers(self.rules)
        self.assertEqual(doc["source_pages"], 10)
        self.assertEqual(len(doc["checks"]), 6)
        self.assertEqual(tuple(x["header"] for x in doc["checks"]), HEADERS)
        self.assertEqual(doc["scope"]["excluded_implementation_technologies"], ["Java", "PHP"])
        self.assertEqual(doc["related_main_guide_control"], "NICS-WEB-4.5.3.4")
        self.assertTrue(all("CR-05" in item["related_rule_ids"] for item in doc["checks"]))
        self.assertIn("CR-01", doc["checks"][1]["related_rule_ids"])
        self.assertIn("IN-02", doc["checks"][0]["related_rule_ids"])
        self.assertTrue(any("unsafe-eval" in c for c in doc["checks"][0]["implementation_cautions"]))
        self.assertTrue(any("geolocation=(self)" in c for c in doc["checks"][5]["implementation_cautions"]))

    def test_review_queue_no_compliance_or_language_specific_java(self):
        mapped = header_review_hints(self.rules)
        self.assertEqual(set(mapped), {r["id"] for r in self.rules})
        self.assertEqual(len(mapped["CR-05"]), 6)
        self.assertEqual(len(mapped["CR-01"]), 1)
        self.assertEqual(len(mapped["IN-02"]), 1)
        self.assertTrue(all("status" not in item for group in mapped.values() for item in group))

    def test_default_all_unassessed(self):
        report = build_appendix3(self.rules)
        self.assertEqual(report["header_count"], 6)
        self.assertEqual(report["status_counts"], {"not_assessed": 6})
        self.assertEqual(validate_appendix3(self.rules, report), [])
        self.assertEqual(review_from_report(report), {"checks": []})

    def test_pass_requires_actual_https_response_evidence(self):
        row = {"id": "NICS-WEB-A3-CSP", "status": "pass",
               "reason": "比對了同一環境中真實 CSP 回應與實際資源載入",
               "reviewer": "資安審核者", "verified_on": "2026-10-20",
               "environment": "測試環境 HTTPS /app",
               "observed_value": "default-src 'self'; script-src 'self'",
               "evidence": ["appsettings.production.json#SecurityHeaders"],
               "http_response_evidence": ["ART-200 /app HTTPS 200 Content-Security-Policy"]}
        report = build_appendix3(self.rules, {"checks": [row]})
        self.assertEqual(report["status_counts"]["pass"], 1)
        self.assertEqual(report["status_counts"]["not_assessed"], 5)
        self.assertEqual(validate_appendix3(self.rules, report), [])
        self.assertEqual(review_from_report(report), {"checks": [row]})
        without_http = dict(row, http_response_evidence=[])
        with self.assertRaises(ValueError):
            build_appendix3(self.rules, {"checks": [without_http]})
        without_environment = dict(row, environment="")
        with self.assertRaises(ValueError):
            build_appendix3(self.rules, {"checks": [without_environment]})

    def test_source_only_fail_can_be_recorded_without_claiming_runtime_validation(self):
        bad = {"id": "NICS-WEB-A3-CSP", "status": "fail",
               "reason": "已發現設定檔使用過度寬鬆的策略（仍待確認部署）",
               "reviewer": "資安審查者", "verified_on": "2026-10-20",
               "observed_value": "script-src * 'unsafe-eval'",
               "evidence": ["web.config:50"], "http_response_evidence": []}
        result = build_appendix3(self.rules, {"checks": [bad]})
        self.assertEqual(result["status_counts"]["fail"], 1)
        self.assertEqual(validate_appendix3(self.rules, result), [])
        unknown = dict(bad, id="NICS-WEB-A3-UNKNOWN")
        with self.assertRaises(ValueError):
            build_appendix3(self.rules, {"checks": [unknown]})

    def test_review_requires_a_real_reviewer_and_date(self):
        row = {"id": "NICS-WEB-A3-HSTS", "status": "review",
               "reason": "只看到了 IIS 設定，缺部署 HTTP 回應",
               "reviewer": "資安審核者", "verified_on": "2026-10-20",
               "evidence": ["web.config:18"], "http_response_evidence": []}
        res = build_appendix3(self.rules, {"checks": [row]})
        self.assertEqual(res["status_counts"]["review"], 1)
        self.assertEqual(validate_appendix3(self.rules, res), [])
        damaged = copy.deepcopy(res)
        damaged["status_counts"]["pass"] = 6
        self.assertTrue(validate_appendix3(self.rules, damaged))
        tampered = copy.deepcopy(res)
        tampered["checks"][0]["status"] = "pass"
        self.assertTrue(validate_appendix3(self.rules, tampered))


if __name__ == "__main__":
    unittest.main()
