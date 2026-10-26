"""跨平台執行器與唯讀相依檢查的回歸測試。"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from check_python_env import check_environment, satisfies


class PythonEnvironmentTests(unittest.TestCase):
    def test_requirement_version_bounds(self):
        self.assertTrue(satisfies("4.26.0", ">=4.18,<5"))
        self.assertTrue(satisfies("0.34.0", ">=0.34,<1"))
        self.assertFalse(satisfies("4.17.9", ">=4.18,<5"))
        self.assertFalse(satisfies("5.0.0", ">=4.18,<5"))
        self.assertFalse(satisfies("4.18.0rc1", ">=4.18,<5"))

    def test_missing_dependency_is_reported_without_installing(self):
        with tempfile.TemporaryDirectory() as tmp:
            req = Path(tmp) / "requirements.txt"
            req.write_text("PyYAML>=6.0,<7\n", encoding="utf-8")
            with patch("check_python_env.metadata.version", side_effect=__import__("importlib").metadata.PackageNotFoundError):
                errors = check_environment(req)
            self.assertTrue(any("PyYAML" in message for message in errors))


@unittest.skipIf(os.name == "nt", "POSIX runner 只在 Unix 類系統執行")
class PosixPythonRunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name) / "skill root with spaces"
        (root / "scripts").mkdir(parents=True)
        shutil.copy(ROOT / "scripts" / "run-python.sh", root / "scripts" / "run-python.sh")
        shutil.copy(ROOT / "scripts" / "check_python_env.py", root / "scripts" / "check_python_env.py")
        shutil.copy(ROOT / "requirements.txt", root / "requirements.txt")
        self.runner = root / "scripts" / "run-python.sh"
        self.script = root / "scripts" / "echo.py"
        self.script.write_text("import sys\nprint('RUN:' + '|'.join(sys.argv[1:]))\n", encoding="utf-8")
        self.bin = Path(self.tmp.name) / "bin"
        self.bin.mkdir()

    def run_runner(self, *args, env=None):
        environ = os.environ.copy()
        environ.pop("SECURITY_CODE_REVIEW_PYTHON", None)
        environ.pop("SECURITY_CODE_REVIEW_PYTHON_PINNED", None)
        environ.pop("VIRTUAL_ENV", None)
        environ.pop("CONDA_PREFIX", None)
        if env:
            environ.update(env)
        return subprocess.run(["/bin/sh", str(self.runner), *args], text=True, capture_output=True, env=environ)

    def test_python3_is_used_when_python_is_unavailable(self):
        fake = self.bin / "python"
        fake.write_text("#!/bin/sh\nexit 42\n", encoding="utf-8")
        fake.chmod(0o755)
        proxy = self.bin / "python3"
        proxy.write_text("#!/bin/sh\nexec " + repr(sys.executable) + " \"$@\"\n", encoding="utf-8")
        proxy.chmod(0o755)
        env = {"PATH": str(self.bin)}
        checked = self.run_runner("--check", env=env)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        executed = self.run_runner(str(self.script), "value with spaces", env=env)
        self.assertEqual(executed.returncode, 0, executed.stderr)
        self.assertIn("RUN:value with spaces", executed.stdout)

    def test_no_python_exits_without_running_script(self):
        outcome = self.run_runner(str(self.script), env={"PATH": str(self.bin)})
        self.assertEqual(outcome.returncode, 2)
        self.assertIn("Python 3.10+", outcome.stderr)
        self.assertNotIn("RUN:", outcome.stdout)

    def test_existing_queue_is_preserved(self):
        queue = ROOT / "scripts" / "review_queue.py"
        if not queue.is_file():
            self.skipTest("完整專案才有審查佇列")
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "target"
            target.mkdir()
            cmd = [str(queue), "--target", str(target), "--init", "--batch-size", "1"]
            created = self.run_runner(*cmd)
            self.assertEqual(created.returncode, 0, created.stderr)
            assessment = target / "reports" / "security-code-review" / "assessment.json"
            original = assessment.read_text(encoding="utf-8")
            repeated = self.run_runner(*cmd)
            self.assertEqual(repeated.returncode, 0, repeated.stderr)
            self.assertEqual(assessment.read_text(encoding="utf-8"), original)

    def test_invalid_preference_falls_back_to_python3(self):
        proxy = self.bin / "python3"
        proxy.write_text("#!/bin/sh\nexec " + repr(sys.executable) + " \"$@\"\n", encoding="utf-8")
        proxy.chmod(0o755)
        env = {"PATH": str(self.bin), "SECURITY_CODE_REVIEW_PYTHON": "/no/such/python"}
        resolved = self.run_runner("--resolve", env=env)
        self.assertEqual(resolved.returncode, 0, resolved.stderr)
        self.assertEqual(Path(resolved.stdout.strip()).resolve(), Path(sys.executable).resolve())
        self.assertIn("preferred_python_unavailable", resolved.stderr)

    def test_resolve_then_pin_survives_path_changes(self):
        resolved = self.run_runner("--resolve")
        self.assertEqual(resolved.returncode, 0, resolved.stderr)
        chosen = resolved.stdout.strip()
        self.assertTrue(Path(chosen).is_absolute())
        pinned = self.run_runner(str(self.script), "locked", env={
            "PATH": str(self.bin), "SECURITY_CODE_REVIEW_PYTHON_PINNED": chosen,
        })
        self.assertEqual(pinned.returncode, 0, pinned.stderr)
        self.assertIn("RUN:locked", pinned.stdout)

    def test_broken_pin_fails_closed_without_fallback(self):
        result = self.run_runner(str(self.script), env={
            "SECURITY_CODE_REVIEW_PYTHON_PINNED": "/missing/python",
        })
        self.assertEqual(result.returncode, 2)
        self.assertIn("pinned_python_unavailable", result.stderr)
        self.assertNotIn("RUN:", result.stdout)

    def test_virtual_environment_candidate_is_detected(self):
        venv_bin = Path(self.tmp.name) / "venv" / "bin"
        venv_bin.mkdir(parents=True)
        fake = venv_bin / "python"
        fake.write_text("#!/bin/sh\nexec " + repr(sys.executable) + " \"$@\"\n", encoding="utf-8")
        fake.chmod(0o755)
        checked = self.run_runner("--check", env={
            "PATH": str(self.bin), "VIRTUAL_ENV": str(venv_bin.parent),
        })
        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_missing_packages_never_trigger_automatic_install(self):
        (self.runner.parent.parent / "requirements.txt").write_text(
            "this_missing_pkg>=1,<2\n", encoding="utf-8"
        )
        proxy = self.bin / "python3"
        proxy.write_text("#!/bin/sh\nexec " + repr(sys.executable) + " \"$@\"\n", encoding="utf-8")
        proxy.chmod(0o755)
        outcome = self.run_runner(str(self.script), env={"PATH": str(self.bin)})
        self.assertEqual(outcome.returncode, 2)
        self.assertIn("requirements.txt", outcome.stderr)
        self.assertNotIn("RUN:", outcome.stdout)


@unittest.skipUnless(os.name == "nt", "Windows cmd 只在 Windows 執行")
class WindowsPythonRunnerTests(unittest.TestCase):
    def test_cmd_runner_check_and_argument_forwarding(self):
        runner = ROOT / "scripts" / "run-python.cmd"
        # run-python.cmd 固定輸出 UTF-8；不可讓繁中 Windows 的 CP950 預設解碼管線處理。
        # 未指定 encoding 時，subprocess 的 reader thread 可能拋 UnicodeDecodeError，
        # 但 returncode 仍為 0，因此必須同時驗證實際取得的 UTF-8 訊息。
        checked = subprocess.run(
            ["cmd", "/c", str(runner), "--check"],
            capture_output=True, text=True, encoding="utf-8", errors="strict",
        )
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertIn("PASS: Python", checked.stdout)
        self.assertIn("相依套件", checked.stdout)
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "echo args.py"
            script.write_text("import sys\nprint('ARGS:' + '|'.join(sys.argv[1:]))\nprint('中文輸出正常')\n", encoding="utf-8")
            result = subprocess.run(["cmd", "/c", str(runner), str(script), "hello world"],
                                    capture_output=True, text=True, encoding="utf-8")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("ARGS:hello world", result.stdout)
            self.assertIn("中文輸出正常", result.stdout)

    def test_preferred_python_fallback_and_pinned_runtime(self):
        runner = ROOT / "scripts" / "run-python.cmd"
        env = os.environ.copy()
        env.pop("SECURITY_CODE_REVIEW_PYTHON_PINNED", None)
        env["SECURITY_CODE_REVIEW_PYTHON"] = r"C:\\missing-python\\python.exe"
        resolved = subprocess.run(
            ["cmd", "/c", str(runner), "--resolve"], capture_output=True,
            text=True, encoding="utf-8", env=env,
        )
        self.assertEqual(resolved.returncode, 0, resolved.stderr)
        chosen = resolved.stdout.strip()
        self.assertTrue(Path(chosen).is_absolute())
        self.assertTrue(Path(chosen).is_file())
        self.assertIn("preferred_python_unavailable", resolved.stderr)
        env.pop("SECURITY_CODE_REVIEW_PYTHON", None)
        env["SECURITY_CODE_REVIEW_PYTHON_PINNED"] = chosen
        pinned = subprocess.run(
            ["cmd", "/c", str(runner), "--check"], capture_output=True,
            text=True, encoding="utf-8", env=env,
        )
        self.assertEqual(pinned.returncode, 0, pinned.stderr)
        self.assertIn(chosen.casefold(), pinned.stdout.casefold())

    def test_broken_pin_never_falls_back(self):
        env = os.environ.copy()
        env["SECURITY_CODE_REVIEW_PYTHON_PINNED"] = r"C:\\missing-python\\python.exe"
        result = subprocess.run(
            ["cmd", "/c", str(ROOT / "scripts" / "run-python.cmd"), "--check"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", env=env,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("pinned_python_unavailable", result.stderr)


if __name__ == "__main__":
    unittest.main()
