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

    def test_multiple_cross_file_rules_keep_independent_candidate_maps(self):
        from review_safety import closure_errors
        index = {
            "schema_version": 3, "cross_file_evidence_version": 0,
            "typed_relationships": [],
            "rule_candidates": {"Safe.cs": [
                {"rule_id": "AC-01"}, {"rule_id": "AU-01"}]},
            "cross_file_call_hints": {"Safe.cs": [{
                "id": "call-1", "possible_targets": [{"path": "App.csproj"}]}]},
        }
        snapshot = {"source_hashes": {"Safe.cs": "hash", "App.csproj": "hash"}}
        closures = {}
        checks = []
        for rid in ("AC-01", "AU-01"):
            closures[rid] = {
                "status": "pass",
                "summary": "已追蹤所有實際呼叫路徑與安全控制責任，確認候選關聯。",
                "examined_paths": ["Safe.cs", "App.csproj"],
                "control_owner": "IdentityService",
                "search_summary": "已核對所有必要的來源候選與跨檔呼叫端，無未決問題。",
                "examined_relationship_ids": [], "dismissed_relationships": {},
                "callsite_reviews": {"call-1": {
                    "status": "excluded", "selected_targets": [],
                    "reason": "經核對該呼叫與安全控制不相關，且查明排除理由與來源責任。"}},
                "open_issues": [],
            }
            checks.append({"id": rid, "status": "pass",
                           "execution": {"state": "completed"}})
        self.assertEqual(closure_errors(
            self.root, {"checks": checks}, index_override=index,
            snapshot_override=snapshot, closures_override=closures), [])

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

    def test_fixed_first_pass_baseline_cannot_be_silently_replaced(self):
        # 僅測不可變錨點；第一輪證據要求由各獨立守門器測試。
        from partial_review import _atomic
        self.prepare()
        path = _category_dir(self.root, "AC") / "assessment.json"
        a = read_category(self.root, "AC", self.catalog)
        for check in a["checks"]:
            check["execution"]["state"] = "completed"
        _atomic(path, a)
        with patch("partial_review_safety._first_pass", return_value=[]):
            first = begin_second_pass(self.root, "AC", self.catalog)
            self.assertFalse(first["already_existed"])
            again = begin_second_pass(self.root, "AC", self.catalog)
            self.assertTrue(again["already_existed"])
            fixed = (_category_dir(self.root, "AC") / BASELINE).read_text("utf-8")
            a["checks"][0]["decision_reason"] = "修訂後的不同判定，不得更換第一次固定的指紋"
            _atomic(path, a)
            with self.assertRaises(ScopeError):
                begin_second_pass(self.root, "AC", self.catalog)
            self.assertEqual((_category_dir(self.root, "AC") /
                              BASELINE).read_text("utf-8"), fixed)

    def test_index_relationship_tamper_blocked_by_seal(self):
        self.prepare()
        path = _shared_path(self.root)
        index = json.loads(path.read_text("utf-8"))
        index["typed_relationships"] = []
        index["tampered"] = True
        path.write_text(json.dumps(index), encoding="utf-8")
        result = validate(self.root, "AC", self.catalog)
        self.assertFalse(result["safety_valid"])
        self.assertIn("完整性校驗失敗", "；".join(result["safety_integrity_errors"]))

    def test_index_is_invalid_after_tampering(self):
        self.prepare()
        index = _shared_path(self.root)
        obj = json.loads(index.read_text(encoding="utf-8"))
        obj["source_hashes"] = {}
        index.write_text(json.dumps(obj), encoding="utf-8")
        result = validate(self.root, "AC", self.catalog)
        self.assertFalse(result["safety_valid"])
        self.assertIn("完整性校驗失敗", "；".join(result["safety_integrity_errors"]))

    def test_second_pass_correction_requires_explicit_revision_and_history(self):
        from adversarial_recheck import digest
        from partial_review import _atomic
        assessment_path = _category_dir(self.root, "AC") / "assessment.json"
        previous = read_category(self.root, "AC", self.catalog)
        first = previous["checks"][0]
        first["status"] = "pass"
        first["execution"]["state"] = "completed"
        previous["checks"][0] = first
        _atomic(assessment_path, previous)
        baseline_path = _category_dir(self.root, "AC") / BASELINE
        _atomic(baseline_path, {"schema_version": 1, "checks": {
            "AC-01": {"status": "pass", "digest": digest(first), "decision_reason": "原先判定"}
        }})
        corrected = json.loads(json.dumps(first))
        corrected["status"] = "fail"
        corrected["finding_ids"] = ["F-01"]
        corrected["decision_reason"] = "第二輪確認授權檢查可能被直接呼叫路徑繞過，已修訂原判定。"
        record = {"outcome": "corrected", "baseline_digest": digest(first),
                  "final_digest": digest(corrected), "final_status": "fail",
                  "contradictions": [{"resolution": "重新閱讀執行路徑後發現已證實的授權缺失"}]}
        path = _category_dir(self.root, "AC") / "payload.json"
        path.write_text(json.dumps({"checks": [corrected],
                                    "findings": [{"id": "F-01", "check_ids": ["AC-01"]}],
                                    "adversarial_reviews": {"AC-01": record}}), encoding="utf-8")
        # 僅隔離測試修訂授權守門；完整證據品質由獨立驗證器測試。
        with patch("partial_review.completion_errors", return_value=[]), \
             patch("partial_review.decision_quality_errors", return_value=[]):
            stage(self.root, "AC", path, self.catalog)
            with self.assertRaises(ScopeError):
                integrate(self.root, "AC", self.catalog)
            result = integrate(self.root, "AC", self.catalog, allow_revision=True)
        self.assertEqual(result["corrected_rule_ids"], ["AC-01"])
        self.assertEqual(read_category(self.root, "AC", self.catalog)["checks"][0]["status"], "fail")
        history = list((_category_dir(self.root, "AC") /
                        "analysis/second-pass-history").glob("*.json"))
        self.assertEqual(len(history), 1)
        self.assertEqual(json.loads(history[0].read_text("utf-8"))["previous_checks"]["AC-01"]["status"], "pass")
        self.assertEqual(self.official.read_text("utf-8"), '{"official":true}')

    def test_second_pass_cannot_demote_existing_fail(self):
        from adversarial_recheck import digest
        from partial_review import _atomic
        assessment_path = _category_dir(self.root, "AC") / "assessment.json"
        previous = read_category(self.root, "AC", self.catalog)
        first = previous["checks"][0]
        first["status"] = "fail"
        first["execution"]["state"] = "completed"
        _atomic(assessment_path, previous)
        _atomic(_category_dir(self.root, "AC") / BASELINE, {
            "schema_version": 1, "checks": {"AC-01": {
                "status": "fail", "digest": digest(first), "decision_reason": "已確認弱點"}
            }})
        corrected = json.loads(json.dumps(first))
        corrected["status"] = "pass"
        record = {"outcome": "corrected", "baseline_digest": digest(first),
                  "final_digest": digest(corrected), "final_status": "pass",
                  "contradictions": [{"resolution": "嘗試降級，應拒絕"}]}
        path = _category_dir(self.root, "AC") / "payload.json"
        path.write_text(json.dumps({"checks": [corrected],
                                    "adversarial_reviews": {"AC-01": record}}), encoding="utf-8")
        with patch("partial_review.completion_errors", return_value=[]), \
             patch("partial_review.decision_quality_errors", return_value=[]):
            stage(self.root, "AC", path, self.catalog)
            with self.assertRaises(ScopeError):
                integrate(self.root, "AC", self.catalog, allow_revision=True)
        self.assertEqual(read_category(self.root, "AC", self.catalog)["checks"][0]["status"], "fail")

    def test_cli_prepare_validate_do_not_enable_partial_report(self):
        script = str(ROOT / "scripts/review_queue.py")
        env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
        cmd = [sys.executable, script, "--target", str(self.root), "--categories", "AC,AU"]
        with patch("analysis_prepare.probe_roslyn", return_value={"available": False}), \
             patch("analysis_prepare.probe_codegraph", return_value={"available": False}):
            self.prepare()
        result = subprocess.run([*cmd, "--validate"], capture_output=True, text=True,
                                encoding="utf-8", env=env, check=False)
        self.assertEqual(result.returncode, 1, result.stderr)
        payload = json.loads(result.stdout)
        self.assertFalse(payload["ready_for_report"])
        self.assertFalse(payload["safety_valid"])
        invalid = subprocess.run([*cmd, "--begin-second-pass"], capture_output=True,
                                 text=True, encoding="utf-8", env=env, check=False)
        self.assertNotEqual(invalid.returncode, 0)
        self.assertEqual(self.official.read_text("utf-8"), '{"official":true}')


if __name__ == "__main__":
    unittest.main()
