"""技術偵測、結構快取、保守變更範圍與工具降級測試。"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from analysis_adapters import ModernDotNetAdapter, probe_codegraph
from analysis_prepare import INDEX_NAME, prepare, source_files
from token_metrics import record_usage


class AnalysisPrepareTests(unittest.TestCase):
    def make_dotnet(self, root: Path, tfm: str = "net8.0"):
        (root / "Sample.csproj").write_text(
            f'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>{tfm}</TargetFramework></PropertyGroup></Project>',
            encoding="utf-8")
        (root / "Service.cs").write_text("public class Service { public void Run() {} }", encoding="utf-8")
        return root

    def test_modern_and_legacy_detection(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self.make_dotnet(Path(temp))
            adapter = ModernDotNetAdapter()
            self.assertTrue(adapter.detect(root)["supported"])
            self.assertEqual(adapter.detect(root)["projects"][0]["target_frameworks"], ["net8.0"])
            (root / "Sample.csproj").write_text(
                '<Project><PropertyGroup><TargetFrameworks>net8.0;net48</TargetFrameworks></PropertyGroup></Project>',
                encoding="utf-8")
            self.assertFalse(adapter.detect(root)["supported"])
            self.assertFalse(ModernDotNetAdapter().detect(Path(temp) / "missing")["supported"])

    def test_fallback_and_incremental_unchanged(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self.make_dotnet(Path(temp))
            with patch("analysis_prepare.probe_roslyn", return_value={"available": False, "reason": "no SDK"}), \
                 patch("analysis_prepare.probe_codegraph", return_value={"available": False, "reason": "no graph"}):
                first = prepare(root, "full")
                self.assertEqual(first["source_file_count"], 2)
                self.assertEqual(first["csharp_file_count"], 1)
                self.assertEqual(first["roslyn_indexed_count"], 0)
                self.assertFalse(first["complete_security_review"])
                self.assertEqual(first["recheck_file_count"], 2)
                self.assertTrue((root / INDEX_NAME).exists())
                second = prepare(root, "incremental")
                self.assertEqual(second["changed_file_count"], 0)
                self.assertEqual(second["recheck_file_count"], 0)
                self.assertEqual(second["roslyn_indexed_count"], 0)
                self.assertFalse((root / "reports/security-code-review/assessment.json").exists())
                (root / "Service.cs").write_text("public class Service { public void Changed() {} }", encoding="utf-8")
                third = prepare(root, "incremental")
                self.assertEqual(third["changed_file_count"], 1)
                self.assertEqual(third["recheck_file_count"], 2)
                self.assertFalse(third["complete_security_review"])

    def test_mixed_vue_rejected_and_analysis_index_not_counted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self.make_dotnet(Path(temp))
            (root / ".codegraph").mkdir()
            (root / ".codegraph" / "index.json").write_text("{}", encoding="utf-8")
            self.assertNotIn(".codegraph/index.json", source_files(root))
            (root / "App.vue").write_text("<template><h1>Test</h1></template>", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Vue"):
                prepare(root)

    def test_legacy_rejected_before_writing_index(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self.make_dotnet(Path(temp), "net48")
            with self.assertRaisesRegex(ValueError, "第一階段"):
                prepare(root)
            self.assertFalse((root / INDEX_NAME).exists())

    def test_codegraph_probe_falls_back_without_index(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch("analysis_adapters.shutil.which", return_value="/bin/codegraph"):
                result = probe_codegraph(Path(temp))
            self.assertFalse(result["available"])

    def test_roslyn_with_real_sdk_when_available(self):
        from analysis_adapters import probe_roslyn
        if not probe_roslyn()["available"]:
            self.skipTest("dotnet SDK 8+ not installed")
        with tempfile.TemporaryDirectory() as temp:
            root = self.make_dotnet(Path(temp))
            with patch("analysis_prepare.probe_codegraph", return_value={"available": False}):
                result = prepare(root, "full")
            self.assertEqual(result["roslyn_indexed_count"], 1, result["roslyn_errors"])
            self.assertFalse(result["roslyn_errors"])
            index = json.loads((root / INDEX_NAME).read_text("utf-8"))
            self.assertIn("Service", [i["name"] for i in index["roslyn_files"]["Service.cs"]["types"]])
            self.assertIn("Run", [i["name"] for i in index["roslyn_files"]["Service.cs"]["methods"]])

    def test_usage_metrics_accept_observed_only(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "reports/security-code-review/analysis/token-usage.jsonl"
            row = record_usage(path, executor="Codex CLI", run_id="one", input_tokens=30,
                               output_tokens=12, cached_input_tokens=5, tool_calls=7)
            self.assertEqual(row["input_tokens"], 30)
            self.assertEqual(json.loads(path.read_text("utf-8").splitlines()[0])["tool_calls"], 7)
            with self.assertRaises(ValueError):
                record_usage(path, executor="Codex CLI", run_id="two",
                             input_tokens=2, output_tokens=4, cached_input_tokens=5)


if __name__ == "__main__":
    unittest.main()
