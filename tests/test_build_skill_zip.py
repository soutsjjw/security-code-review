"""上傳用 Zip 只收錄執行期檔案，且必須符合 Claude Desktop 的檔案數與 frontmatter 限制。"""
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/lib"))
from build_skill_zip import (ALLOWED_FRONTMATTER, MAX_FILES, SKILL_NAME, build,
                             upload_files, upload_skill_md)

SKILL = ('---\nname: demo\nversion: 1.0.0\ndescription: 示範\n'
         'argument-hint: "[path]"\n---\n\n# Demo\n見 [流程](docs/a.md)。\n')


def _frontmatter(text: str) -> dict:
    return yaml.safe_load(text.split("---\n")[1])


class BuildSkillZipTests(unittest.TestCase):
    def _package(self, root: Path) -> None:
        files = {
            "SKILL.md": SKILL,
            "CLAUDE.md": "dev guide\n",
            "docs/a.md": "接著讀 [b](b.md#section)\n",
            "docs/b.md": "end\n",
            "docs/c.md": "unreferenced\n",
            "docs/d.md": "used by script\n",
            "scripts/lib/m.py": 'DOC = "docs/d.md"\n',
            "tests/test_m.py": "pass\n",
            "examples/e.json": "{}\n",
        }
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")

    def test_keeps_runtime_files_and_referenced_docs_only(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            self._package(root)
            self.assertEqual(upload_files(root), [
                "SKILL.md", "docs/a.md", "docs/b.md", "docs/d.md", "scripts/lib/m.py"])

    def test_moves_unsupported_frontmatter_into_metadata(self):
        result = _frontmatter(upload_skill_md(SKILL))
        self.assertLessEqual(set(result), ALLOWED_FRONTMATTER)
        self.assertEqual(result["name"], "demo")
        self.assertEqual(result["metadata"], {"version": "1.0.0", "argument-hint": "[path]"})
        self.assertTrue(upload_skill_md(SKILL).endswith("# Demo\n見 [流程](docs/a.md)。\n"))

    def test_rejects_missing_frontmatter_and_existing_metadata(self):
        with self.assertRaises(ValueError):
            upload_skill_md("# no frontmatter\n")
        with self.assertRaises(ValueError):
            upload_skill_md("---\nname: x\nmetadata:\n  a: b\nversion: 1\n---\n")

    def test_zip_has_single_skill_folder_and_rewritten_skill_md(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "pkg"
            root.mkdir()
            self._package(root)
            output = Path(t) / "out" / "skill.zip"
            build(output, root)
            with zipfile.ZipFile(output) as archive:
                names = archive.namelist()
                skill = archive.read(f"{SKILL_NAME}/SKILL.md").decode("utf-8")
            self.assertTrue(all(n.startswith(f"{SKILL_NAME}/") and "\\" not in n for n in names))
            self.assertIn("metadata", _frontmatter(skill))
            self.assertEqual((root / "SKILL.md").read_text(encoding="utf-8"), SKILL)

    def test_repository_fits_upload_limits(self):
        files = upload_files(ROOT)
        self.assertLessEqual(len(files), MAX_FILES)
        self.assertIn("SKILL.md", files)
        skill = upload_skill_md((ROOT / "SKILL.md").read_text(encoding="utf-8"))
        self.assertLessEqual(set(_frontmatter(skill)), ALLOWED_FRONTMATTER)
        for rel in files:
            self.assertFalse(rel.startswith(("tests/", "examples/")), rel)


if __name__ == "__main__":
    unittest.main()
