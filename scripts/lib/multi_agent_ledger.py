#!/usr/bin/env python3
"""多代理 Ledger 的路徑、狀態讀寫、Git／來源快照與現行計畫核對；不建立或啟動子代理。

測試替換本層函式（例如 git_state）時請 patch 本模組；planning／workers 一律以 ml.<名稱> 取用。
"""
from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

from multi_agent_contract import digest
from multi_agent_guard import probe_errors, protected_report_digest, sha
from source_reader import source_digest
from source_coverage import expected_paths
from scope_paths import relative_path
from review_core import ANALYSIS_ROOT, load_json_object as _read, REPORT_ROOT, write_json_atomic

ANALYSIS = ANALYSIS_ROOT
LEDGER = ANALYSIS / "multi-agent/ledger.json"
PROBE = ANALYSIS / "multi-agent/capability-probe.json"
SNAPSHOT = ANALYSIS / "review-snapshot.json"
INDEX = ANALYSIS / "structure-index.json"
REPORT = REPORT_ROOT
HIGH_RISK = re.compile(r"auth|identity|session|credential|permission|access|"
                       r"controller|endpoint|request|input|upload|serializ|"
                       r"deserializ|middleware|token|password|config", re.I)
RETRY_LIMIT = 2


def write_ledger_json(path: Path, data: dict) -> None:
    # Main-agent-only metadata. Do not use this for assessment/Manifest/Journal.
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError("狀態路徑不可為符號連結")
    write_json_atomic(path, data)


def git_state(root: Path) -> dict:
    try:
        head = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=False)
    except OSError:
        # Git is supplementary to the authoritative source snapshot, not a prerequisite
        # for enforced read-only Codex workers. Never invent a revision.
        return {"head": None, "worktree_digest": None}
    if head.returncode:
        return {"head": None, "worktree_digest": None}
    status = subprocess.run(["git", "-C", str(root), "status", "--porcelain=v1",
                             "--untracked-files=all", "-z"],
                            capture_output=True, check=False)
    if status.returncode:
        raise ValueError("無法核對 Git 工作目錄狀態")
    entries = status.stdout.split(b"\x00")
    # Reports are controlled review artifacts and do not count as changed target source.
    filtered = sorted(e for e in entries if e and not (
        e[3:].replace(b"\\", b"/").startswith(REPORT_ROOT.as_posix().encode() + b"/")
    ))
    return {"head": head.stdout.strip(), "worktree_digest":
            hashlib.sha256(b"\x00".join(filtered)).hexdigest()}


def source_snapshot(root: Path) -> tuple[dict, dict, dict]:
    snap = _read(root / SNAPSHOT)
    index = _read(root / INDEX)
    hashes = snap.get("source_hashes")
    if not isinstance(hashes, dict) or hashes != index.get("source_hashes"):
        raise ValueError("來源快照與結構索引不一致")
    assessment = _read(root / REPORT / "assessment.json")
    excluded = [relative_path(root, row["path"], root_allowed=True)
                for row in (assessment.get("scope_details") or {}).get("excluded_paths", [])]
    if set(hashes) != expected_paths(root, excluded):
        raise ValueError("完整來源清單已異動")
    for relative, sha in hashes.items():
        p = (root / relative).resolve()
        if (not p.is_relative_to(root) or not p.is_file() or p.is_symlink()
                or source_digest(p.read_bytes()) != sha):
            raise ValueError("來源 SHA256 無法核對：" + relative)
    actual_head = git_state(root)["head"]
    if actual_head and snap.get("git_revision") != actual_head:
        raise ValueError("來源快照 Git Revision 與實際 HEAD 不一致")
    # Without Git, the recorded source hashes remain mandatory and authoritative;
    # the lack of Git metadata is disclosed through the ledger git_state.
    return snap, index, assessment


def ledger_fingerprint(snap: dict) -> str:
    return digest({"git_revision": snap.get("git_revision"),
                   "source_hashes": snap["source_hashes"],
                   "excluded_paths": snap.get("excluded_paths", [])})


def active_plan(root: Path) -> tuple[dict, dict]:
    state = _read(root / LEDGER)
    snap, _, _ = source_snapshot(root)
    probe = _read(root / PROBE) if (root / PROBE).exists() else {}
    if state.get("integration") is not None:
        raise ValueError("主代理正式整合窗口尚未結束，禁止分派／收件子代理")
    if state.get("probe_digest") != digest(probe):
        raise ValueError("能力 probe 變更，Ledger 失效；不得沿用舊派工")
    if state.get("report_guard") != protected_report_digest(root):
        raise ValueError("正式 assessment／Manifest／Journal 或其他審查工件被異動")
    if state.get("multi_agent_enabled"):
        errors = probe_errors(root, probe)
        if errors:
            raise ValueError("Codex 能力試跑已失效：" + "；".join(errors))
    if (state.get("snapshot_fingerprint") != ledger_fingerprint(snap)
            or state.get("git_state") != git_state(root)):
        raise ValueError("來源或 Git 狀態異動；停用既有子代理結果並重新查證")
    for ident, row in state.get("tasks", {}).items():
        if row.get("result_digest"):
            candidate = root / ANALYSIS / "multi-agent/results" / (ident + ".json")
            if (not candidate.is_file() or candidate.is_symlink()
                    or candidate.stat().st_size > 2_000_000
                    or digest(_read(candidate)) != row["result_digest"]):
                raise ValueError("已接受 Worker 證據遺失或被改寫：" + ident)
    return state, snap
