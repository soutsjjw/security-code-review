"""MSBuild 匯入、父目錄屬性、條件式 TFM 與保守失敗測試。"""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from analysis_adapters import ModernDotNetAdapter
from analysis_prepare import INDEX_NAME, prepare
from assessment_consistency import detect_language_framework, project_placeholder_errors


class MSBuildTFMTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.project = self.root / "src" / "Web" / "Web.csproj"
        self.project.parent.mkdir(parents=True)
        self.project.write_text('<Project Sdk="Microsoft.NET.Sdk.Web"></Project>', encoding="utf-8")

    def mock_evaluation(self, *, target="net10.0", multi="", version="", returncode=0):
        output = json.dumps({"Properties": {
            "TargetFramework": target,
            "TargetFrameworks": multi,
            "TargetFrameworkVersion": version,
        }})
        return patch("analysis_adapters.subprocess.run",
                     return_value=subprocess.CompletedProcess(["dotnet"], returncode,
                                                            stdout=output, stderr=""))

    def test_parent_directory_build_props_net10_and_read_only_msbuild(self):
        (self.root / "Directory.Build.props").write_text(
            "<Project><PropertyGroup><TargetFramework>net10.0</TargetFramework>"
            "</PropertyGroup></Project>", encoding="utf-8")
        with patch("analysis_adapters.shutil.which", return_value="dotnet"), self.mock_evaluation() as run:
            detected = ModernDotNetAdapter().detect(self.root)
            self.assertTrue(detected["supported"], detected)
            self.assertEqual(detected["projects"][0]["target_frameworks"], ["net10.0"])
            self.assertEqual(detect_language_framework(self.root),
                             "ASP.NET Core（C#，net10.0）")
        cmd = run.call_args.args[0]
        self.assertEqual(cmd[1:3], ["msbuild", str(self.project)])
        self.assertTrue(any(arg.startswith("-getProperty:") for arg in cmd))
        self.assertFalse(any(arg.lower() in ("build", "restore") or arg.startswith("-target")
                             for arg in cmd))
        self.assertEqual(run.call_args.kwargs["cwd"], self.project.parent)

    def test_nested_props_in_parent_requires_evaluation(self):
        (self.root / "src" / "Directory.Build.props").write_text(
            "<Project><PropertyGroup><TargetFramework>net10.0</TargetFramework>"
            "</PropertyGroup></Project>", encoding="utf-8")
        with patch("analysis_adapters.shutil.which", return_value="dotnet"), self.mock_evaluation():
            detected = ModernDotNetAdapter().detect(self.root)
        self.assertEqual(detected["projects"][0]["target_frameworks"], ["net10.0"])

    def test_explicit_import_and_conditional_msbuild_properties(self):
        self.project.write_text(
            '<Project Sdk="Microsoft.NET.Sdk"><Import Project="../../Shared.props"/>'
            '</Project>', encoding="utf-8")
        (self.root / "Shared.props").write_text(
            '<Project><PropertyGroup Condition="\'$(Configuration)\' == \'Debug\'">'
            '<TargetFrameworks>net8.0;net10.0</TargetFrameworks></PropertyGroup></Project>',
            encoding="utf-8")
        with patch("analysis_adapters.shutil.which", return_value="dotnet"), \
                self.mock_evaluation(target="", multi="net8.0;net10.0"):
            detected = ModernDotNetAdapter().detect(self.root)
        self.assertEqual(detected["projects"][0]["target_frameworks"], ["net10.0", "net8.0"])
        self.assertTrue(detected["supported"])

    def test_legacy_multitarget_import_remains_blocked_without_index(self):
        (self.root / "Directory.Build.props").write_text(
            "<Project><PropertyGroup><TargetFrameworks>net10.0;net48</TargetFrameworks>"
            "</PropertyGroup></Project>", encoding="utf-8")
        with patch("analysis_adapters.shutil.which", return_value="dotnet"), \
                self.mock_evaluation(target="", multi="net10.0;net48"), \
                patch("analysis_prepare.probe_codegraph", return_value={"available": False}), \
                patch("analysis_prepare.probe_roslyn", return_value={"available": False}):
            detected = ModernDotNetAdapter().detect(self.root)
            self.assertFalse(detected["supported"])
            with self.assertRaisesRegex(ValueError, "第一階段"):
                prepare(self.root)
        self.assertFalse((self.root / INDEX_NAME).exists())

    def test_project_conditional_tfm_must_use_evaluated_value(self):
        self.project.write_text(
            '<Project Sdk="Microsoft.NET.Sdk">'
            '<PropertyGroup Condition="\'$(Configuration)\' == \'Debug\'">'
            '<TargetFramework>net10.0</TargetFramework></PropertyGroup>'
            '<PropertyGroup Condition="\'$(Configuration)\' == \'Release\'">'
            '<TargetFramework>net48</TargetFramework></PropertyGroup></Project>',
            encoding="utf-8")
        with patch("analysis_adapters.shutil.which", return_value="dotnet"), \
                self.mock_evaluation(target="net48"):
            detected = ModernDotNetAdapter().detect(self.root)
        self.assertFalse(detected["supported"])
        self.assertEqual(detected["projects"][0]["target_frameworks"], ["net48"])

    def test_import_without_dotnet_fails_closed_and_preserves_log(self):
        (self.root / "Directory.Build.props").write_text(
            "<Project><PropertyGroup><TargetFramework>net10.0</TargetFramework>"
            "</PropertyGroup></Project>", encoding="utf-8")
        latest = self.root / "reports/security-code-review/logs/latest.json"
        latest.parent.mkdir(parents=True)
        latest.write_text('{"status":"blocked"}', encoding="utf-8")
        with patch("analysis_adapters.shutil.which", return_value=None):
            detected = ModernDotNetAdapter().detect(self.root)
            self.assertFalse(detected["supported"])
            self.assertIn("dotnet SDK", detected["projects"][0]["reason"])
            with self.assertRaisesRegex(ValueError, "第一階段"):
                prepare(self.root)
        self.assertEqual(latest.read_text("utf-8"), '{"status":"blocked"}')
        self.assertFalse((self.root / INDEX_NAME).exists())

    def test_msbuild_failure_and_unresolved_expression_never_guess(self):
        (self.root / "Directory.Build.props").write_text(
            "<Project><PropertyGroup><TargetFramework>net10.0</TargetFramework>"
            "</PropertyGroup></Project>", encoding="utf-8")
        with patch("analysis_adapters.shutil.which", return_value="dotnet"), \
                self.mock_evaluation(returncode=1):
            error = ModernDotNetAdapter().detect(self.root)
        self.assertFalse(error["supported"])
        self.assertIn("MSBuild TFM 評估失敗", error["projects"][0]["reason"])
        with patch("analysis_adapters.shutil.which", return_value="dotnet"), \
                self.mock_evaluation(target="$(SomeProperty)"):
            error = ModernDotNetAdapter().detect(self.root)
        self.assertFalse(error["supported"])
        self.assertIn("未展開", error["projects"][0]["reason"])
        with patch("analysis_adapters.shutil.which", return_value=None):
            self.assertTrue(project_placeholder_errors({
                "language_framework": detect_language_framework(self.root)
            }))

    def test_literal_direct_tfm_works_without_sdk_and_net10_is_modern(self):
        self.project.write_text(
            '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
            '<TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>',
            encoding="utf-8")
        with patch("analysis_adapters.shutil.which", return_value=None):
            detected = ModernDotNetAdapter().detect(self.root)
        self.assertTrue(detected["supported"])
        self.assertEqual(detected["projects"][0]["target_frameworks"], ["net10.0"])

    def test_real_msbuild_evaluates_imports_without_build_when_sdk_available(self):
        if not shutil.which("dotnet"):
            self.skipTest("dotnet SDK unavailable")
        (self.root / "Directory.Build.props").write_text(
            '<Project><PropertyGroup><TargetFramework>net8.0</TargetFramework>'
            '</PropertyGroup></Project>', encoding="utf-8")
        self.project.write_text('<Project Sdk="Microsoft.NET.Sdk"/>', encoding="utf-8")
        detected = ModernDotNetAdapter().detect(self.root)
        self.assertTrue(detected["supported"], detected)
        self.assertEqual(detected["projects"][0]["target_frameworks"], ["net8.0"])
        # 再檢查明確 <Import>，不依賴 Directory.Build.props 的搜尋慣例。
        (self.root / "Directory.Build.props").unlink()
        (self.root / "Shared.props").write_text(
            '<Project><PropertyGroup><TargetFramework>net8.0</TargetFramework>'
            '</PropertyGroup></Project>', encoding="utf-8")
        self.project.write_text(
            '<Project Sdk="Microsoft.NET.Sdk"><Import Project="../../Shared.props"/>'
            '</Project>', encoding="utf-8")
        imported = ModernDotNetAdapter().detect(self.root)
        self.assertTrue(imported["supported"], imported)
        self.assertEqual(imported["projects"][0]["target_frameworks"], ["net8.0"])


if __name__ == "__main__":
    unittest.main()
