"""DP-01／DP-04 掃描證實相依弱點路徑：lockfile 行 + SHA256 吻合的掃描工件只能支持 fail。"""
import copy
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/lib"))

from control_outcome_evidence import outcome_errors
from dependency_scan_evidence import excerpt_packages, scan_proven_errors
from file_review_integrity import verified_file_rule_reviews
from review_core import REPORT_ROOT, snapshot_fingerprint
from review_fixture import make_file_review

LOCKFILE = """{
  "version": 1,
  "dependencies": {
    "net10.0": {
      "System.Security.Cryptography.Pkcs": {
        "type": "Transitive",
        "resolved": "10.0.0",
        "contentHash": "abc=="
      },
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[13.0.3, )",
        "resolved": "13.0.3",
        "contentHash": "def=="
      }
    }
  }
}
"""
PKCS = (5, 7)  # "System.Security.Cryptography.Pkcs": { … "resolved": "10.0.0"
NEWTONSOFT = (10, 13)
SCAN_OUTPUT = """The following sources were used:
   https://api.nuget.org/v3/index.json

Project `Web` has the following vulnerable packages
   [net10.0]:
   Transitive Package                       Resolved   Severity   Advisory URL
   > System.Security.Cryptography.Pkcs      10.0.0     High       https://github.com/advisories/GHSA-555p-m4v6-cqxv
"""
ARTIFACT_ID = "scan:dotnet-list-package-vulnerable-20261031"
ARTIFACT_NAME = "scan-dotnet-list-package-vulnerable-20261031.txt"
DATE = "2026-10-31"


class ScanProvenDependencyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "src").mkdir()
        (self.root / "src/packages.lock.json").write_text(LOCKFILE, encoding="utf-8")
        (self.root / "Directory.Packages.props").write_text(
            "<Project>\n  <PropertyGroup>\n"
            "    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>\n"
            "  </PropertyGroup>\n</Project>\n", encoding="utf-8")
        self.artifact = self.root / REPORT_ROOT / "artifacts" / ARTIFACT_NAME
        self.write_artifact(SCAN_OUTPUT)

    def write_artifact(self, text):
        self.artifact.parent.mkdir(parents=True, exist_ok=True)
        self.artifact.write_text(text, encoding="utf-8")

    def scan_evidence(self, sha=None):
        return {"kind": "scan", "artifact_id": ARTIFACT_ID,
                "sha256": sha or hashlib.sha256(self.artifact.read_bytes()).hexdigest(),
                "description": "dotnet list package --vulnerable --include-transitive 輸出",
                "collected_on": DATE, "source_version": "HEAD"}

    @staticmethod
    def source(path, lines):
        return {"kind": "source", "path": path, "line_start": lines[0], "line_end": lines[1],
                "description": "lockfile 弱點套件解析版本", "collected_on": DATE,
                "source_version": "HEAD"}

    def excerpt(self, path, lines):
        rows = (self.root / path).read_text(encoding="utf-8").splitlines()
        return rows[lines[0] - 1:lines[1]]

    def errors(self, rid="DP-01", status="fail", path="src/packages.lock.json", lines=PKCS,
               evidence=None):
        evidence = [self.scan_evidence()] if evidence is None else evidence
        return scan_proven_errors(self.root, rid, status, path, self.excerpt(path, lines), evidence)

    # --- 證據路徑本身 -------------------------------------------------------------

    def test_lockfile_line_with_valid_scan_artifact_supports_fail(self):
        self.assertEqual(self.errors(), [])
        self.assertEqual(self.errors(rid="DP-04"), [])
        self.assertEqual(excerpt_packages("src/packages.lock.json", self.excerpt("src/packages.lock.json", PKCS)),
                         {("System.Security.Cryptography.Pkcs", "10.0.0")})

    def test_other_manifest_formats_are_parsed(self):
        self.assertEqual(excerpt_packages("Web.csproj", [
            '<PackageReference Include="System.Security.Cryptography.Pkcs" Version="10.0.0" />']),
            {("System.Security.Cryptography.Pkcs", "10.0.0")})
        self.assertEqual(excerpt_packages("Directory.Packages.props", [
            '<PackageVersion Include="Newtonsoft.Json"', '  Version="13.0.3" />']),
            {("Newtonsoft.Json", "13.0.3")})
        self.assertEqual(excerpt_packages("Web.csproj", [
            '<PackageReference Include="Foo" Version="$(FooVersion)" />']), set())
        self.assertEqual(excerpt_packages("libman.json", ['"library": "jquery@3.4.1",']),
                         {("jquery", "3.4.1")})
        self.assertEqual(excerpt_packages("package-lock.json", [
            '"node_modules/lodash": {', '  "version": "4.17.20",',
            '  "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",']),
            {("lodash", "4.17.20")})

    def test_pass_or_review_is_rejected(self):
        for status in ("pass", "review"):
            self.assertIn("只能支持 fail", "；".join(self.errors(status=status)))

    def test_missing_tampered_or_unrelated_artifact_is_rejected(self):
        self.assertIn("SHA256", "；".join(self.errors(evidence=[self.scan_evidence(sha="0" * 64)])))
        no_sha = self.scan_evidence()
        no_sha.pop("sha256")
        self.assertIn("sha256", "；".join(self.errors(evidence=[no_sha])))
        self.assertIn("kind=scan", "；".join(self.errors(evidence=[])))
        # 套件與版本不在輸出內：Newtonsoft.Json 13.0.3 沒有列為弱點。
        self.assertIn("找不到片段的套件與版本", "；".join(self.errors(lines=NEWTONSOFT)))
        # 只有描述文字，沒有命令輸出特徵。
        self.write_artifact("已執行掃描，System.Security.Cryptography.Pkcs 10.0.0 有弱點\n")
        self.assertIn("命令輸出特徵", "；".join(self.errors()))
        self.artifact.unlink()
        self.assertIn("找不到", "；".join(self.errors(evidence=[
            {"kind": "scan", "artifact_id": ARTIFACT_ID, "sha256": "a" * 64}])))
        bad_id = {"kind": "scan", "artifact_id": "scan:../../etc/passwd", "sha256": "a" * 64}
        self.assertIn("artifact_id", "；".join(self.errors(evidence=[bad_id])))

    def test_central_version_switch_is_rejected(self):
        self.assertIn("集中版本開關不算", "；".join(self.errors(path="Directory.Packages.props", lines=(3, 3))))

    def test_other_rules_and_wide_excerpts_are_rejected(self):
        for rid in ("SI-01", "AC-01", "DP-02"):
            self.assertIn("只適用 DP-01／DP-04", "；".join(self.errors(rid=rid)))
        self.assertIn("超過", "；".join(scan_proven_errors(
            self.root, "DP-01", "fail", "src/packages.lock.json", ["  "] * 31, [self.scan_evidence()])))

    # --- 逐檔 rule_reviews 與 orphan 檢查 ------------------------------------------

    def assessment(self, rid="DP-01", status="fail", result="fail", lines=PKCS, scan=True):
        review = make_file_review(self.root, "src/packages.lock.json", (rid,))
        review["rule_reviews"][0].update({
            "result": result, "line_start": lines[0], "line_end": lines[1],
            "reason": "lockfile 解析的 System.Security.Cryptography.Pkcs 10.0.0 經掃描列為 GHSA High 弱點",
        })
        evidence = [self.source("src/packages.lock.json", lines)] + ([self.scan_evidence()] if scan else [])
        check = {"id": rid, "status": status, "finding_ids": ["F-DP"], "evidence": evidence,
                 "execution": {"state": "completed", "inspected_paths": ["src/packages.lock.json"]}}
        finding = {"id": "F-DP", "check_ids": [rid], "evidence": [self.source("src/packages.lock.json", lines)]}
        return {"checks": [check], "findings": [finding],
                "file_reviews": [review, make_file_review(self.root, "Directory.Packages.props")]}

    def verify(self, assessment):
        expected = {"src/packages.lock.json", "Directory.Packages.props"}
        return verified_file_rule_reviews(assessment, self.root, expected)

    def test_file_review_accepts_scan_proven_fail(self):
        for rid in ("DP-01", "DP-04"):
            verified, errors = self.verify(self.assessment(rid=rid))
            self.assertEqual(errors, [], rid)
            self.assertEqual(verified["src/packages.lock.json"], {rid})

    def test_file_review_rejects_pass_review_or_missing_scan(self):
        cases = (
            self.assessment(status="pass", result="pass"),
            self.assessment(status="review", result="review"),
            self.assessment(status="fail", result="review"),
            self.assessment(scan=False),
        )
        for assessment in cases:
            verified, errors = self.verify(assessment)
            self.assertNotIn("src/packages.lock.json", verified)
            text = "；".join(errors)
            self.assertIn("未經逐檔驗證的 inspected_paths", text)

    def test_file_review_rejects_tampered_artifact(self):
        assessment = self.assessment()
        self.write_artifact(SCAN_OUTPUT + "   > Extra.Package 1.0.0 Low\n")
        verified, errors = self.verify(assessment)
        self.assertNotIn("src/packages.lock.json", verified)
        self.assertIn("SHA256", "；".join(errors))

    def test_file_review_rejects_central_version_switch(self):
        assessment = self.assessment()
        props = make_file_review(self.root, "Directory.Packages.props", ("DP-01",))
        props["rule_reviews"][0].update({"result": "fail", "line_start": 3, "line_end": 3})
        assessment["file_reviews"][1] = props
        assessment["checks"][0]["execution"]["inspected_paths"].append("Directory.Packages.props")
        verified, errors = self.verify(assessment)
        self.assertNotIn("Directory.Packages.props", verified)
        self.assertIn("集中版本開關不算", "；".join(errors))

    def test_other_rules_cannot_use_lockfile_path(self):
        # SI-01 有自己的 CI 路徑限制；lockfile 加上掃描工件仍不得通過。
        verified, errors = self.verify(self.assessment(rid="SI-01"))
        self.assertNotIn("src/packages.lock.json", verified)
        self.assertIn("只有宣告／無關程式碼", "；".join(errors))

    # --- Q3 control-verifications ------------------------------------------------

    def q3(self, check=None, record=None, finding_lines=PKCS):
        lock = "src/packages.lock.json"
        source_hash = hashlib.sha256((self.root / lock).read_bytes()).hexdigest()
        snapshot = {"git_revision": "abc123", "source_hashes": {lock: source_hash}}
        point = {"path": lock, "line_start": PKCS[0], "line_end": PKCS[1]}
        check = check or self.assessment()["checks"][0]
        record = record or {
            "status": "fail", "git_revision": "abc123",
            "snapshot_fingerprint": snapshot_fingerprint(snapshot),
            "source_hashes": {lock: source_hash},
            "entry_points": [point], "failure_points": [point], "protected_operations": [point],
            "failure_mode": "unsafe_configuration",
            "failure_reason": "lockfile 解析 System.Security.Cryptography.Pkcs 10.0.0，掃描輸出列為 GHSA High 弱點",
            "search_summary": "已執行 dotnet list package --vulnerable --include-transitive，並核對 lockfile 解析版本",
            "bypass_scenarios": [{
                "scenario": "transitive_dependency", "outcome": "confirmed_vulnerability",
                "reason": "遞移相依解析到含已知弱點的 10.0.0，建置產物會載入該版本",
                "evidence": [point],
            }],
            "open_issues": [],
        }
        finding = {"id": "F-DP", "check_ids": [check["id"]],
                   "evidence": [self.source(lock, finding_lines)]}
        return outcome_errors(self.root, {"control_outcome_version": 1}, snapshot, [check],
                              {check["id"]: record}, audits_override={},
                              assessment_override={"findings": [finding]}), record

    def test_q3_accepts_scan_proven_lockfile_failure_point(self):
        errors, _ = self.q3()
        self.assertEqual(errors, [])

    def test_q3_requires_scan_artifact_scenario_and_finding_overlap(self):
        _, record = self.q3()
        check = self.assessment(scan=False)["checks"][0]
        self.assertIn("kind=scan", "；".join(self.q3(check=check, record=copy.deepcopy(record))[0]))
        bad = copy.deepcopy(record)
        bad["bypass_scenarios"][0]["scenario"] = "alternate_entry"
        self.assertIn("confirmed_vulnerability", "；".join(self.q3(record=bad)[0]))
        bad = copy.deepcopy(record)
        bad["bypass_scenarios"][0]["evidence"] = [{"path": "src/packages.lock.json",
                                                    "line_start": 10, "line_end": 13}]
        self.assertIn("同一套件清單行", "；".join(self.q3(record=bad)[0]))
        self.assertIn("Finding 證據不一致", "；".join(self.q3(finding_lines=NEWTONSOFT)[0]))
        sealed = self.assessment()["checks"][0]
        self.write_artifact(SCAN_OUTPUT.replace("10.0.0", "9.0.0"))
        self.assertIn("SHA256", "；".join(self.q3(check=sealed, record=copy.deepcopy(record))[0]))


if __name__ == "__main__":
    unittest.main()
