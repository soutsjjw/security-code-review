"""完成條件：逐條證據、review 區分與 70/70 假性完成回歸測試。"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/lib"))

from review_completion import completion_errors
from review_queue import build_queue, load_rules
from review_fixture import make_file_review


def check(rid, *, status="review", evidence=None):
    return {
        "id": rid, "status": status,
        "decision_reason": f"已驗證 {rid} 的伺服端控制；仍缺少部署環境的授權測試結果待確認",
        "evidence": evidence if evidence is not None else [{
            "kind": "source", "path": "Auth.cs", "line_start": 1, "line_end": 1,
            "description": f"依來源追查 {rid} 的處理流程與條件分支",
        }],
        "execution": {
            "state": "completed", "methods": ["source_review"],
            "summary": f"針對 {rid} 實際檢閱安全控制，追蹤呼叫路徑及依據",
            "inspected_paths": ["Auth.cs"],
        },
    }


class ReviewCompletionTests(unittest.TestCase):
    def test_review_with_source_evidence_and_specific_gap_is_allowed(self):
        row = check("AC-01")
        self.assertEqual(completion_errors([row]), [])

    def test_inspected_paths_alone_do_not_count_as_review_evidence(self):
        row = check("AC-01", evidence=[])
        self.assertIn("缺少具體可追溯", " ".join(completion_errors([row])))

    def test_unlocated_other_evidence_cannot_justify_completed(self):
        row = check("AC-01", evidence=[{"kind": "other", "description": "聲稱已檢核但沒提供實際定位"}])
        self.assertIn("缺少具體可追溯", " ".join(completion_errors([row])))

    def test_specific_external_artifact_can_support_review(self):
        row = check("AC-01", evidence=[{
            "kind": "policy", "artifact_id": "ACCESS-POLICY-2026",
            "description": "已取得組織權限政策文件，仍需部署驗證",
        }])
        self.assertEqual(completion_errors([row]), [])

    def test_pass_without_located_evidence_is_rejected(self):
        row = check("AC-01", status="pass", evidence=[{
            "kind": "other", "description": "口頭聲稱沒有漏洞"
        }])
        self.assertIn("缺少具體可追溯", " ".join(completion_errors([row])))

    def test_mass_template_even_with_changing_rule_ids_is_rejected(self):
        ids = ["AC-01", "AU-01", "IN-01", "CR-01", "EH-01", "LG-01",
               "DP-01", "PD-01", "BC-01", "SI-01"]
        checks = [check(rid) for rid in ids]
        errors = completion_errors(checks)
        self.assertIn("共用制式執行摘要", " ".join(errors))
        self.assertIn("共用制式判定理由", " ".join(errors))
        self.assertIn("共用制式證據描述", " ".join(errors))

    def test_demo_bypass_is_explicit(self):
        checks = [check("AC-01", evidence=[])]
        self.assertEqual(completion_errors(checks, allow_demo=True), [])

    def test_70_completed_and_100pct_files_is_not_ready_without_rule_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Auth.cs").write_text("options.ExpireTimeSpan = TimeSpan.FromMinutes(20);\n", encoding="utf-8")
            _, rules = load_rules()
            checks = [check(rule["id"], evidence=[]) for rule in rules]
            checks[0]["evidence"] = [{
                "kind": "source", "path": "Auth.cs", "line_start": 1, "line_end": 1,
                "description": "已核對 Auth.cs 中的授權分支與處理責任"
            }]
            for other in checks[1:]:
                other["execution"]["inspected_paths"] = []
            assessment = {"checks": checks, "file_reviews": [
                make_file_review(root, "Auth.cs", [rules[0]["id"]])
            ]}
            queue = build_queue(assessment, rules, 10, source_root=root)
            self.assertEqual(queue["completed"], 70)
            self.assertEqual(queue["source_coverage"]["missing_source_file_count"], 0)
            self.assertFalse(queue["ready_for_report"])
            self.assertTrue(queue["rule_integrity_errors"])


if __name__ == "__main__":
    unittest.main()
