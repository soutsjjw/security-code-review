"""validate_assessment.py 必須拒絕常見的無效 assessment 輸入；不需要受測專案。"""
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts/validate_assessment.py"
BASE = json.loads((ROOT / "examples/assessment.example.json").read_text("utf-8"))


def _mutated(change):
    data = copy.deepcopy(BASE)
    change(data)
    return data


CASES = [
    ("70 entries in Review, format only", BASE, True),
    ("duplicate/missing ID must fail",
     _mutated(lambda d: d["checks"][0].update(id=d["checks"][1]["id"])), False),
    ("Pass without evidence must fail", _mutated(lambda d: d["checks"][0].update(status="pass")), False),
    ("Fail without evidence must fail", _mutated(lambda d: d["checks"][0].update(status="fail")), False),
    ("N/A without clear reason must fail",
     _mutated(lambda d: d["checks"][0].update(status="na", applicability_reason="無")), False),
    ("expired exception must fail",
     _mutated(lambda d: d.update(exceptions=[{
         "id": "EX-1", "rule_id": "AU-02", "approver": "資安主管", "accepted_by": "系統擁有者",
         "expires_on": "2020-01-01", "compensating_controls": "MFA", "justification": "測試"}])), False),
]


class NegativeAssessmentCases(unittest.TestCase):
    def test_validator_accepts_or_rejects_each_case(self):
        for label, data, expected_ok in CASES:
            with self.subTest(label), tempfile.TemporaryDirectory() as d:
                path = Path(d) / "assessment.json"
                path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
                run = subprocess.run([sys.executable, str(VALIDATOR), str(path), "--allow-demo"],
                                     capture_output=True, text=True, encoding="utf-8", errors="replace")
                self.assertEqual(run.returncode == 0, expected_ok, run.stdout + run.stderr)


if __name__ == "__main__":
    unittest.main()
