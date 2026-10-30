"""scope_details.projects：由 .csproj 盤點，未宣告時拒絕交付。"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_ROOT / 'scripts/lib'))
from scope_inventory import detect_projects, scope_project_issues


def make_solution(root: Path):
    for rel, name in (("src/Web", "Web"), ("src/Application", "Application"), ("tests/Web.Tests", "Web.Tests"),
                      (".", "Root")):
        d = root / rel
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{name}.csproj").write_text("<Project/>", encoding="utf-8")
    for ignored in ("bin", "obj", "node_modules/pkg", "src/Web/bin"):
        d = root / ignored
        d.mkdir(parents=True, exist_ok=True)
        (d / "Ignored.csproj").write_text("<Project/>", encoding="utf-8")


class ProjectDetectionTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        make_solution(self.root)

    def test_detects_real_projects_and_skips_build_dirs(self):
        rows = detect_projects(self.root)
        self.assertEqual({(r["name"], r["path"]) for r in rows},
                         {("Web", "src/Web"), ("Application", "src/Application"),
                          ("Web.Tests", "tests/Web.Tests"), ("Root", ".")})

    def test_undeclared_projects_are_rejected(self):
        errors, _ = scope_project_issues({}, self.root)
        self.assertEqual(len(errors), 1)
        self.assertIn("4 個 .csproj", errors[0])
        errors, _ = scope_project_issues({"scope_details": {"projects": []}}, self.root)
        self.assertEqual(len(errors), 1)

    def test_complete_declaration_passes(self):
        projects = [{"name": r["name"], "path": r["path"]} for r in detect_projects(self.root)]
        self.assertEqual(scope_project_issues({"scope_details": {"projects": projects}}, self.root), ([], []))

    def test_partial_declaration_warns_about_missing(self):
        projects = [{"name": "Web", "path": "src/Web"}]
        errors, warnings = scope_project_issues({"scope_details": {"projects": projects}}, self.root)
        self.assertEqual(errors, [])
        self.assertEqual(len(warnings), 1)
        self.assertIn("Application", warnings[0])

    def test_windows_style_declared_path_matches(self):
        projects = [{"name": r["name"], "path": r["path"].replace("/", "\\")} for r in detect_projects(self.root)]
        self.assertEqual(scope_project_issues({"scope_details": {"projects": projects}}, self.root), ([], []))

    def test_no_csproj_means_no_requirement(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(scope_project_issues({}, Path(tmp)), ([], []))

    def test_cli_lists_projects(self):
        run = subprocess.run([sys.executable, str(SKILL_ROOT / "scripts/scope_inventory.py"),
                              "--target", str(self.root)], capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(len(json.loads(run.stdout)), 4)

    def test_cli_emits_utf8_for_names_not_representable_in_cp950(self):
        # Windows Python 預設 stdout 可能是 cp950，非 CP950 字元需仍能產生 JSON。
        project_dir = self.root / "src" / "Audit🔐"
        project_dir.mkdir(parents=True)
        (project_dir / "Audit🔐.csproj").write_text("<Project/>", encoding="utf-8")
        run = subprocess.run([sys.executable, str(SKILL_ROOT / "scripts/scope_inventory.py"),
                              "--target", str(self.root)], capture_output=True,
                             text=True, encoding="utf-8")
        self.assertEqual(run.returncode, 0, run.stderr)
        projects = json.loads(run.stdout)
        self.assertTrue(any(p["name"] == "Audit🔐" for p in projects))

    def test_init_prefills_projects(self):
        run = subprocess.run([sys.executable, str(SKILL_ROOT / "scripts/review_queue.py"),
                              "--target", str(self.root), "--init", "--batch-size", "1", "--compact"],
                             capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(run.returncode, 0, run.stderr)
        data = json.loads((self.root / "reports/security-code-review/assessment.json").read_text("utf-8"))
        self.assertEqual(len(data["scope_details"]["projects"]), 4)


if __name__ == "__main__":
    unittest.main()
