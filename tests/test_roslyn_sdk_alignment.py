"""Roslyn SDK/TFM compatibility and writable-cache fallback on .NET 8/10."""
from __future__ import annotations

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

from analysis_adapters import probe_roslyn
from analysis_prepare import _run_roslyn, prepare, INDEX_NAME


class RoslynSdkAlignmentTests(unittest.TestCase):
    def fixture(self, root: Path, framework: str) -> None:
        (root / "App.csproj").write_text(
            f'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
            f'<TargetFramework>{framework}</TargetFramework></PropertyGroup></Project>',
            encoding="utf-8")
        (root / "Target.cs").write_text(
            "public class Target { public void Execute() { } }\n", encoding="utf-8")
        (root / "Caller.cs").write_text(
            "public class Caller { public void Run(Target service) { service.Execute(); } }\n",
            encoding="utf-8")

    def test_sdk_probe_uses_isolated_directory(self):
        with patch("analysis_adapters.shutil.which", return_value="dotnet"):
            with patch("analysis_adapters.subprocess.run",
                       return_value=subprocess.CompletedProcess(
                           args=["dotnet", "--version"], returncode=0,
                           stdout="10.0.100\n")) as mocked:
                probe = probe_roslyn()
        self.assertEqual(probe["target_framework"], "net10.0")
        self.assertEqual(probe["sdk_version"], "10.0.100")
        cwd = mocked.call_args.kwargs["cwd"]
        self.assertTrue(Path(cwd).name.startswith("security-review-sdk-probe-"))

    def test_build_aborts_if_selected_sdk_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.fixture(Path(tmp), "net10.0")
            requested = {"available": True, "executable": "dotnet",
                         "sdk_version": "10.0.100", "target_framework": "net10.0"}
            wrong = subprocess.CompletedProcess(
                args=["dotnet", "--version"], returncode=0,
                stdout="8.0.408\n", stderr="")
            with patch("analysis_prepare.subprocess.run", return_value=wrong):
                data, reasons = _run_roslyn(Path(tmp), ["Target.cs"], requested, no_cache=True)
            self.assertEqual(data, {})
            self.assertIn("版本", str(reasons))

    def test_real_dotnet_10_indexes_net10_project_with_local_global_json(self):
        probe = probe_roslyn()
        if not probe.get("available") or int(probe["sdk_version"].split(".")[0]) < 10:
            self.skipTest(".NET 10 SDK unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root, "net10.0")
            # An audited project can pin a different SDK; it must not redirect
            # which Roslyn DLLs the *skill's own* indexer is built against.
            (root / "global.json").write_text(
                json.dumps({"sdk": {"version": "8.0.100", "rollForward": "disable"}}),
                encoding="utf-8")
            with patch("analysis_prepare.probe_codegraph",
                       return_value={"available": False}):
                report = prepare(root, "full")
            self.assertEqual(report["roslyn_indexed_count"], 2, report["roslyn_errors"])
            self.assertEqual(report["roslyn_errors"], [], report["roslyn_errors"])
            index = json.loads((root / INDEX_NAME).read_text("utf-8"))
            self.assertIn("Caller.cs", index["roslyn_files"])
            self.assertIn("Target.cs", index["roslyn_files"])
            self.assertTrue(index["cross_file_call_hints"].get("Caller.cs"))

    def test_unwritable_cache_retries_with_isolated_scratch(self):
        probe = probe_roslyn()
        if not probe.get("available"):
            self.skipTest("dotnet SDK unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root, "net10.0" if int(probe["sdk_version"].split(".")[0]) >= 10
                         else "net8.0")
            inaccessible = root / "not-a-directory"
            inaccessible.write_text("no cache beneath this file", encoding="utf-8")
            with (patch("analysis_prepare.Path.home", return_value=inaccessible),
                  patch.dict(os.environ, {"SECURITY_CODE_REVIEW_ROSLYN_CACHE": "1"})):
                data, issues = _run_roslyn(root, ["Caller.cs", "Target.cs"], probe)
            self.assertEqual(set(data), {"Caller.cs", "Target.cs"}, issues)
            self.assertIn("權限不足", str(issues))


if __name__ == "__main__":
    unittest.main()
