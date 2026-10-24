"""P3：分類安全控制、跨檔結案、第二輪門檻及隔離證據回歸測試。"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from partial_review import initialize, read_category, stage, integrate, _category_dir
from partial_review_safety import (prepare_index, begin_second_pass, validate, _evidence,
                                   _shared_path, _index, _first_pass, BASELINE)
from review_scope import ScopeError, load_catalog


class PartialSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = load_catalog()

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        (self.root / "App.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
            '<TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>',
            encoding="utf-8")
        (self.root / "Safe.cs").write_text(
            "public static class Safe { public static bool IsAuthorized(bool allowed) => allowed; }\n",
            encoding="utf-8")
        self.official = self.root / "reports/security-code-review/assessment.json"
        self.official.parent.mkdir(parents=True)
        self.official.write_text('{"official":true}', encoding="utf-8")
        initialize(self.root, ("AC", "AU"), self.catalog)

    def prepare(self):
        with patch("analysis_prepare.probe_roslyn", return_value={"available": False}), \
             patch("analysis_prepare.probe_codegraph", return_value={"available": False}):
            return prepare_index(self.root, self.catalog)

    def test_shared_index_reused_and_full_review_unmodified(self):
        value = self.prepare()
        self.assertFalse(value["reused"])
        again = self.prepare()
        self.assertTrue(again["reused"])
        self.assertTrue(_shared_path(self.root).is_file())
        self.assertFalse((self.root / "reports/security-code-review/analysis/structure-index.json").exists())
        self.assertEqual(self.official.read_text("utf-8"), '{"official":true}')

    def test_missing_index_fails_closed(self):
        results = validate(self.root, "AC", self.catalog)
        self.assertFalse(results["first_pass_complete"])
        self.assertFalse(results["safety_valid"])
        self.assertFalse(results["ready_for_report"])
        self.assertTrue(any("--prepare" in msg for msg in results["safety_integrity_errors"]))

    def test_p3_safety_records_stage_integrate_isolated(self):
        self.prepare()
        payload = {
            "closures": {"AC-01": {"status": "review", "open_issues": ["尚未追查設定責任"]}},
            "control_verifications": {"AC-01": {"status": "review"}},
            "decision_audits": {"AC-01": {"status": "review"}},
        }
        path = _category_dir(self.root, "AC") / "payload.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        stage(self.root, "AC", path, self.catalog)
        result = integrate(self.root, "AC", self.catalog)
        self.assertEqual(result["saved_safety_records"]["closures"], 1)
        self.assertFalse(result["ready_for_report"])
        self.assertEqual(_evidence(self.root, "AC", "closures")["AC-01"]["status"], "review")
        self.assertEqual(_evidence(self.root, "AU", "closures"), {})
        self.assertEqual(self.official.read_text("utf-8"), '{"official":true}')

    def test_reject_cross_category_records_and_second_pass_without_baseline(self):
        payload_path = _category_dir(self.root, "AC") / "payload.json"
        for payload in ({"closures": {"AU-01": {}}},
                        {"control_verifications": {"AU-01": {"status": "pass"}}},
                        {"adversarial_reviews": {"AC-01": {"outcome": "confirmed"}}}):
            payload_path.write_text(json.dumps(payload), encoding="utf-8")
            with self.subTest(payload=payload), self.assertRaises(ScopeError):
                stage(self.root, "AC", payload_path, self.catalog)

    def test_evidence_conflict_preserves_previous_record_and_staged_data(self):
        self.prepare()
        path = _category_dir(self.root, "AC") / "payload.json"
        path.write_text(json.dumps({"closures": {"AC-01": {"status": "review"}}}), encoding="utf-8")
        stage(self.root, "AC", path, self.catalog)
        integrate(self.root, "AC", self.catalog)
        path.write_text(json.dumps({"closures": {"AC-01": {"status": "pass"}}}), encoding="utf-8")
        stage(self.root, "AC", path, self.catalog)
        with self.assertRaises(ScopeError):
            integrate(self.root, "AC", self.catalog)
        self.assertEqual(_evidence(self.root, "AC", "closures")["AC-01"]["status"], "review")
        self.assertTrue((_category_dir(self.root, "AC") / "analysis/staged/pending.json").is_file())

    def test_first_pass_cannot_start_with_pending_rules(self):
        self.prepare()
        with self.assertRaises(ScopeError):
            begin_second_pass(self.root, "AC", self.catalog)
        self.assertFalse((_category_dir(self.root, "AC") / BASELINE).exists())

    def test_fake_completed_checks_cannot_bypass_control_review(self):
        self.prepare()
        assessment_file = _category_dir(self.root, "AC") / "assessment.json"
        a = read_category(self.root, "AC", self.catalog)
        for check in a["checks"]:
            check["execution"]["state"] = "completed"
            check["execution"]["inspected_paths"] = ["Safe.cs"]
            check["execution"]["methods"] = ["實際原始碼閱讀"]
            check["execution"]["summary"] = "檢查安全控制與所有授權與設定路徑，仍需外部確認結果。"
            check["decision_reason"] = "待確認：環境部署與安全控制交界，尚未取得證實工件。"
        assessment_file.write_text(json.dumps(a, ensure_ascii=False), encoding="utf-8")
        result = validate(self.root, "AC", self.catalog)
        self.assertFalse(result["safety_valid"])
        self.assertFalse(result["first_pass_complete"])
        self.assertTrue(any("缺少" in m or "尚未" in m for m in result["safety_integrity_errors"]))
        with self.assertRaises(ScopeError):
            begin_second_pass(self.root, "AC", self.catalog)

    def test_index_is_invalid_after_tampering(self):
        self.prepare()
        index = _shared_path(self.root)
        obj = json.loads(index.read_text(encoding="utf-8"))
        obj["source_hashes"] = {}
        index.write_text(json.dumps(obj), encoding="utf-8")
        result = validate(self.root, "AC", self.catalog)
        self.assertFalse(result["safety_valid"])
        self.assertIn("不一致", "；".join(result["safety_integrity_errors"]))

    def test_cli_prepare_validate_do_not_enable_partial_report(self):
        script = str(ROOT / "scripts/review_queue.py")
        env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
        cmd = [sys.executable, script, "--target", str(self.root), "--categories", "AC,AU"]
        with patch("analysis_prepare.probe_roslyn", return_value={"available": False}), \
             patch("analysis_prepare.probe_codegraph", return_value={"available": False}):
            self.prepare()
        result = subprocess.run([*cmd, "--validate"], capture_output=True, text=True,
                                encoding="utf-8", env=env, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertFalse(payload["ready_for_report"])
        self.assertFalse(payload["safety_valid"])
        invalid = subprocess.run([*cmd, "--begin-second-pass"], capture_output=True,
                                 text=True, encoding="utf-8", env=env, check=False)
        self.assertNotEqual(invalid.returncode, 0)
        self.assertEqual(self.official.read_text("utf-8"), '{"official":true}')


if __name__ == "__main__":
    unittest.main()
