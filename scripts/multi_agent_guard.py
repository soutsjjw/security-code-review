#!/usr/bin/env python3
"""Security boundaries for untrusted review workers; metadata is not a sandbox."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path
from source_reader import read_source_text

REPORT = Path("reports/security-code-review")
PROBE_TTL_SECONDS = 24 * 3600

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def runtime_binding() -> str | None:
    # A host without a verifiable Codex executable must use the single-agent path.
    try:
        run = subprocess.run(["codex", "--version"], capture_output=True,
                             text=True, timeout=8, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return run.stdout.strip() if run.returncode == 0 and run.stdout.strip() else None

def probe_errors(root: Path, probe: dict, *, required: bool = True) -> list[str]:
    errors = []
    if not isinstance(probe, dict) or probe.get("verified") is not True:
        return ["沒有已核實的 Codex 唯讀能力試跑"] if required else []
    from multi_agent_contract import digest
    from multi_agent import CHECKS
    if any(probe.get("checks", {}).get(k) is not True for k in CHECKS):
        errors.append("能力試跑條件不完整")
    observed = runtime_binding()
    if not observed or observed != probe.get("codex_version"):
        errors.append("Codex 執行器版本不符或無法核實")
    issued = probe.get("verified_at")
    if type(issued) not in (float, int) or time.time() - issued > PROBE_TTL_SECONDS or issued > time.time() + 30:
        errors.append("能力試跑已過期或時間無效")
    path = probe.get("trace_path")
    try:
        candidate = Path(path).resolve(strict=True) if isinstance(path, str) else None
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
