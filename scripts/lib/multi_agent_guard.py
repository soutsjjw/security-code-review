#!/usr/bin/env python3
"""Security boundaries for untrusted review workers; metadata is not a sandbox."""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path
from source_reader import read_source_text
from review_core import REPORT_ROOT, sha256_bytes as sha

CHECKS = ("parallel_dispatch", "independent_context", "single_layer",
          "enforced_read_only", "structured_result", "failure_recovery",
          "first_pass_result_isolation")
# Claude Code 的工具白名單能強制唯讀，卻無法限制 Read 的路徑，因此不能保證第二輪
# Worker 看不到第一輪結論；Claude Code 只核可第一輪分片，第二輪由主代理執行。
EXECUTORS = ("codex", "claude-code")
REQUIRED_CHECKS = {"codex": CHECKS,
                   "claude-code": tuple(c for c in CHECKS if c != "first_pass_result_isolation")}
_CLAUDE_EXECPATH_VERSION = re.compile(r"[\\/]claude-code[\\/](\d+\.\d+\.\d+)[\\/]")

REPORT = REPORT_ROOT
PROBE_TTL_SECONDS = 24 * 3600

def exclusive_ledger(function):
    """Cross-process exclusive metadata mutation; lock is never auto-stolen."""
    from functools import wraps

    @wraps(function)
    def guarded(root: Path, *args, **kwargs):
        directory = root.resolve() / REPORT / "analysis/multi-agent"
        directory.mkdir(parents=True, exist_ok=True)
        if directory.is_symlink():
            raise ValueError("多代理工作目錄不可為符號連結")
        lock = directory / ".exclusive-writer.lock"
        try:
            fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as exc:
            raise ValueError("另一程序正在更新 Ledger，拒絕同時 claim／accept") from exc
        try:
            os.write(fd, b"main-agent-ledger-lock\n")
            return function(root, *args, **kwargs)
        finally:
            os.close(fd)
            lock.unlink(missing_ok=True)

    return guarded


def runtime_binding(executor: str = "codex") -> str | None:
    """回傳目前實際執行器的版本識別；無法核實時回傳 None，主代理須走單代理流程。"""
    if executor == "claude-code":
        # 只在 Claude Code 程序內（含其啟動的子程序）才可核可；優先取實際執行檔版本，
        # 因為 PATH 上的 claude CLI 可能與桌面 app 內建的執行器版本不同。
        if os.environ.get("CLAUDECODE") != "1":
            return None
        match = _CLAUDE_EXECPATH_VERSION.search(os.environ.get("CLAUDE_CODE_EXECPATH", ""))
        if match:
            return f"{match.group(1)} (Claude Code)"
        command = ["claude", "--version"]
    elif executor == "codex":
        command = ["codex", "--version"]
    else:
        return None
    try:
        run = subprocess.run(command, capture_output=True, text=True, timeout=8, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return run.stdout.strip() if run.returncode == 0 and run.stdout.strip() else None


def probe_executor(probe: dict) -> str:
    """舊版 probe 沒有 executor 欄位，一律視為 Codex。"""
    executor = probe.get("executor", "codex") if isinstance(probe, dict) else "codex"
    return executor if executor in EXECUTORS else "unknown"


def probe_version(probe: dict) -> str | None:
    key = "codex_version" if probe_executor(probe) == "codex" else "executor_version"
    value = probe.get(key) if isinstance(probe, dict) else None
    return value if isinstance(value, str) else None


def second_pass_executor_errors(probe: dict) -> list[str]:
    """第二輪 Worker 必須能強制隔離第一輪結果；目前只有 Codex 的工作目錄隔離符合。"""
    if probe_executor(probe) != "codex":
        return ["此執行器無法強制隔離第一輪結果；第二輪由主代理依 second_pass_layers.py 執行"]
    return []


def probe_errors(root: Path, probe: dict, *, required: bool = True) -> list[str]:
    errors = []
    if not isinstance(probe, dict) or probe.get("verified") is not True:
        return ["沒有已核實的唯讀能力試跑"] if required else []
    executor = probe_executor(probe)
    if executor not in REQUIRED_CHECKS:
        return ["能力試跑的執行器不受支援"]
    checks = probe.get("checks")
    if (not isinstance(checks, dict) or set(checks) != set(REQUIRED_CHECKS[executor])
            or any(checks.get(k) is not True for k in REQUIRED_CHECKS[executor])):
        errors.append("能力試跑條件不完整")
    observed = runtime_binding(executor)
    if not observed or observed != probe_version(probe):
        errors.append("執行器版本不符或無法核實")
    issued = probe.get("verified_at")
    if type(issued) not in (float, int) or time.time() - issued > PROBE_TTL_SECONDS or issued > time.time() + 30:
        errors.append("能力試跑已過期或時間無效")
    path = probe.get("trace_path")
    try:
        original = Path(path) if isinstance(path, str) else None
        if original is not None and original.is_symlink():
            errors.append("能力試跑 trace 不可為 symlink")
        candidate = original.resolve(strict=True) if original is not None else None
        if (candidate is None or not candidate.is_file() or candidate.is_symlink()
                or candidate.stat().st_size > 2_000_000
                or sha(candidate.read_bytes()) != probe.get("trace_sha256")):
            errors.append("能力試跑 trace 遺失或 SHA256 不一致")
    except (OSError, ValueError):
        errors.append("能力試跑 trace 無法驗證")
    return errors

def protected_report_digest(root: Path) -> str:
    """Hash every authoritative report file, including newly created/deleted paths.

    Only the non-authoritative multi-agent coordination directory is excluded.
    The probe and trace in that directory are validated independently.
    """
    base = root.resolve() / REPORT
    lines: list[tuple[str, str]] = []
    if not base.exists():
        raise ValueError("正式報告工作目錄不存在")
    for current, dirs, filenames in os.walk(base, followlinks=False):
        here = Path(current)
        if here == base / "analysis" and (here / "multi-agent").is_symlink():
            raise ValueError("多代理協調目錄不可為 symlink")
        dirs[:] = sorted(d for d in dirs if not (
            here == base / "analysis" and d == "multi-agent"))
        for d in dirs:
            if (here / d).is_symlink():
                raise ValueError("正式審查目錄含不允許的 symlink")
        for name in sorted(filenames):
            path = here / name
            if path.is_symlink() or not path.is_file():
                raise ValueError("正式審查檔案含不允許的 symlink")
            lines.append((path.relative_to(base).as_posix(), sha(path.read_bytes())))
    return sha(json.dumps(lines, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))

def challenges_for(root: Path, paths: list[str]) -> tuple[dict, dict]:
    """Task contains line numbers only; expected SHA never leaves the main ledger."""
    import secrets
    display, expected = {}, {}
    for path in paths:
        source = read_source_text(root / path)[0].splitlines()
        indices = sorted(secrets.SystemRandom().sample(
            range(1, len(source) + 1), k=min(3, len(source))))
        display[path] = indices
        expected[path] = {str(n): sha(source[n-1].encode("utf-8")) for n in indices}
    return display, expected

def proof_line_hash(root: Path, path: str, line: int) -> str:
    lines = read_source_text(root / path)[0].splitlines()
    if type(line) is not int or not 1 <= line <= len(lines):
        raise ValueError("引用的原始碼行號無效")
    return sha(lines[line-1].encode("utf-8"))
