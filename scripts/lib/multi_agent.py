#!/usr/bin/env python3
"""Main-agent-only multi-agent ledger. Does not spawn agents or modify assessment."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path

from multi_agent_contract import SECRET, VERSION, digest, validate_worker_result, finding_key
from multi_agent_guard import (CHECKS, challenges_for, exclusive_ledger, probe_errors,
                               proof_line_hash, protected_report_digest, runtime_binding, sha)
from source_reader import source_digest
from source_coverage import expected_paths
from scope_paths import relative_path
from review_core import ANALYSIS_ROOT, REPORT_ROOT, write_json_atomic
from evidence_integrity import MANIFEST

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


def _read(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("JSON root 必須為物件")
    return data


def _write(path: Path, data: dict) -> None:
    # Main-agent-only metadata. Do not use this for assessment/Manifest/Journal.
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError("狀態路徑不可為符號連結")
    write_json_atomic(path, data)


def _git_state(root: Path) -> dict:
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


def _snapshot(root: Path) -> tuple[dict, dict, dict]:
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
    actual_head = _git_state(root)["head"]
    if actual_head and snap.get("git_revision") != actual_head:
        raise ValueError("來源快照 Git Revision 與實際 HEAD 不一致")
    # Without Git, the recorded source hashes remain mandatory and authoritative;
    # the lack of Git metadata is disclosed through the ledger git_state.
    return snap, index, assessment


def _fingerprint(snap: dict) -> str:
    return digest({"git_revision": snap.get("git_revision"),
                   "source_hashes": snap["source_hashes"],
                   "excluded_paths": snap.get("excluded_paths", [])})


def probe_template() -> dict:
    return {"schema_version": VERSION, "codex_version": "",
            "execution_id": "", "checks": {key: False for key in CHECKS},
            "evidence_note": "必須填寫實際執行的獨立子代理試跑觀察，不得只以文件推定", "trace_path": ""}


def record_probe(root: Path, submitted: dict) -> dict:
    checks = submitted.get("checks")
    if (submitted.get("schema_version") != VERSION
            or not isinstance(checks, dict) or set(checks) != set(CHECKS)
            or any(type(x) is not bool for x in checks.values())
            or not isinstance(submitted.get("codex_version"), str)
            or not isinstance(submitted.get("execution_id"), str)
            or len(submitted["execution_id"].strip()) < 4
            or not isinstance(submitted.get("evidence_note"), str)
            or not 30 <= len(submitted["evidence_note"].strip()) <= 2000):
        raise ValueError("P0 試跑紀錄缺少實測資訊")
    # A declaration is not proof: the main agent must retain the independent
    # experiment outputs for review; this gate only refuses missing/failed checks.
    if all(checks.values()) and not submitted["codex_version"].strip():
        raise ValueError("全數核可的 P0 試跑必須填入實際 Codex 版本")
    trace = submitted.get("trace_path")
    current_runtime = runtime_binding()
    if all(checks.values()) and (
            not current_runtime or submitted["codex_version"] != current_runtime):
        raise ValueError("Codex 實際執行器版本無法核實或與 probe 不符")
    try:
        trace_file = Path(trace).resolve(strict=True) if isinstance(trace, str) else None
        if (not trace_file or not trace_file.is_file() or trace_file.is_symlink()
                or trace_file.stat().st_size == 0 or trace_file.stat().st_size > 2_000_000):
            raise ValueError("缺少有效執行器試跑 trace")
        trace_sha = sha(trace_file.read_bytes())
    except (OSError, ValueError):
        if all(checks.values()):
            raise ValueError("已核可試跑必須保留實際執行器 trace")
        trace_file, trace_sha = None, None
    safe = {key: submitted[key] for key in ("schema_version", "codex_version",
                                            "execution_id", "checks", "evidence_note")}
    safe.update(trace_path=str(trace_file) if trace_sha else None,
                trace_sha256=trace_sha, verified_at=time.time())
    raw = json.dumps(safe, ensure_ascii=False)
    if SECRET.search(raw):
        raise ValueError("試跑紀錄疑似包含機敏資訊")
    safe["verified"] = all(checks.values())
    _write(root / PROBE, safe)
    return {"verified": safe["verified"], "failed_checks": [k for k, v in checks.items()
                                                             if not v]}


def _build_tasks(root: Path, snap: dict, index: dict, *, max_agents: int,
                 budget_tokens: int, task_tokens: int, probe_ok: bool) -> dict:
    hashes = snap["source_hashes"]
    ordered = []
    for path in sorted(hashes):
        size = (root / path).stat().st_size
        # Approximation for scheduling only; never reported as measured tokens.
        estimate = max(128, (size + 2) // 3)
        ordered.append({"path": path, "sha256": hashes[path],
                        "estimated_tokens": estimate, "risk": bool(HIGH_RISK.search(path))})
    total = sum(x["estimated_tokens"] for x in ordered)
    max_parallel_by_budget = max(1, budget_tokens // max(task_tokens, 1))
    workers = min(max_agents, len(ordered) or 1, max_parallel_by_budget) if probe_ok else 1
    # Stable deterministic bin packing by estimated cost, not by file count.
    bins: list[dict] = []
    for item in sorted(ordered, key=lambda x: (-x["estimated_tokens"], x["path"])):
        options = [b for b in bins if b["weight"] + item["estimated_tokens"] <= task_tokens]
        if options:
            dest = min(options, key=lambda b: (b["weight"], b["files"][0]["path"]))
        else:
            dest = {"files": [], "weight": 0}
            bins.append(dest)
        dest["files"].append(item)
        dest["weight"] += item["estimated_tokens"]
    for b in bins:
        b["files"].sort(key=lambda x: x["path"])
    bins.sort(key=lambda x: min(e["path"] for e in x["files"]))
    workers = min(workers, len(bins) or 1)
    result = {}
    fp = _fingerprint(snap)
    relations = index.get("cross_file_call_hints") or {}
    candidates = index.get("rule_candidates") or {}
    for i, batch in enumerate(bins):
        owned = {x["path"] for x in batch["files"]}
        consulted: set[str] = set()
        for source in owned:
            for call in relations.get(source, []):
                if not isinstance(call, dict):
                    continue
                for target in call.get("possible_targets", []):
                    other = target.get("path") if isinstance(target, dict) else None
                    if other in hashes and other not in owned:
                        consulted.add(other)
        ident = digest([fp, sorted(owned)])[:20]
        result[ident] = {"schema_version": VERSION, "task_id": ident,
                         "worker_id": f"worker-{i % workers}",
                         "snapshot_fingerprint": fp, "phase": "first_pass",
                         "assigned_paths": [{"path": x["path"], "sha256": x["sha256"],
                                             "estimated_tokens": x["estimated_tokens"],
                                             "candidate_rule_ids": sorted({
                                                 hit["rule_id"] for hit in candidates.get(x["path"], [])
                                                 if isinstance(hit, dict)
                                                 and isinstance(hit.get("rule_id"), str)
                                                 and re.fullmatch(r"(AC|AU|IN|CR|EH|LG|DP|PD|BC|SI)-[0-9]{2}", hit["rule_id"])
                                             })}
                                            for x in batch["files"]],
                         "consult_paths": sorted(consulted),
                         "estimated_tokens": batch["weight"],
                         "prompt_constraints": "read_only_untrusted_source_no_verdict"}
    return {"tasks": result, "workers": workers, "estimated_tokens": total}


@exclusive_ledger
def plan(root: Path, *, max_agents: int = 3, budget_tokens: int = 96000,
         task_tokens: int = 12000, replan: bool = False) -> dict:
    if not 1 <= max_agents <= 8 or budget_tokens < 12000 or not 2000 <= task_tokens <= 30000:
        raise ValueError("workers/budget/task_tokens 不在允許範圍")
    snap, index, _ = _snapshot(root)
    try:
        probe = _read(root / PROBE)
    except FileNotFoundError:
        probe = {}
    # Do not claim that an in-chat declaration enforces a sandbox.
    # Gitless targets still have an exact source inventory and SHA256 snapshot.
    # Only the native executor + forced read-only P0 probe determines availability.
    enabled = not probe_errors(root, probe)
    built = _build_tasks(root, snap, index, max_agents=max_agents,
                         budget_tokens=budget_tokens, task_tokens=task_tokens, probe_ok=enabled)
    current = root / LEDGER
    if current.exists():
        prior = _read(current)
        compatible = (prior.get("snapshot_fingerprint") == _fingerprint(snap)
                      and prior.get("probe_digest") == digest(probe)
                      and prior.get("multi_agent_enabled") == enabled
                      and prior.get("config") == {
                          "max_agents": max_agents, "budget_tokens": budget_tokens,
                          "task_tokens": task_tokens})
        if compatible:
            if prior.get("report_guard") != protected_report_digest(root):
                raise ValueError("既有 Ledger 的正式報告指紋已異動，禁止重新使用")
            return prior
        if not replan:
            raise ValueError("Ledger 的 probe、執行器或分片設定已改變；須明確 --replan")
        if any(row.get("attempts", 0) != 0 or row.get("status") != "pending"
               or row.get("result_digest") for row in prior.get("tasks", {}).values()):
            raise ValueError("已有進行中或已驗證證據，禁止自動重建 Ledger")
        from datetime import datetime, timezone
        history = root / ANALYSIS / "multi-agent/history"
        history.mkdir(parents=True, exist_ok=True)
        import os
        archive = history / ("ledger-" + digest(prior)[:24] + ".json")
        if archive.exists():
            raise ValueError("歷史 Ledger 已存在，拒絕覆蓋")
        os.replace(current, archive)
    state = {"schema_version": VERSION, "snapshot_fingerprint": _fingerprint(snap),
             "probe_digest": digest(probe),
             "report_guard": protected_report_digest(root),
             "integration": None,
             "git_state": _git_state(root), "multi_agent_enabled": enabled,
             "workers": built["workers"],
             "fallback_reason": None if enabled else "原生子代理／唯讀能力試跑未核可，退回單代理",
             "config": {"max_agents": max_agents, "budget_tokens": budget_tokens,
                        "task_tokens": task_tokens},
             "estimated_total_tokens": built["estimated_tokens"], "measured_tokens": 0,
             "window_tokens": 0, "window_charged": 0, "budget_window": 1,
             "tasks": {key: {"task": task, "status": "pending", "attempts": 0,
                             "result_digest": None, "finding_keys": [],
                             "claimed_at": None, "agent_instance_id": None,
                             "challenges": {}, "unresolved_symbols": [], "followup_round": 0}
                       for key, task in built["tasks"].items()}}
    _write(current, state)
    return state


def _active(root: Path) -> tuple[dict, dict]:
    state = _read(root / LEDGER)
    snap, _, _ = _snapshot(root)
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
    if (state.get("snapshot_fingerprint") != _fingerprint(snap)
            or state.get("git_state") != _git_state(root)):
        raise ValueError("來源或 Git 狀態異動；停用既有子代理結果並重新查證")
    for ident, row in state.get("tasks", {}).items():
        if row.get("result_digest"):
            candidate = root / ANALYSIS / "multi-agent/results" / (ident + ".json")
            if (not candidate.is_file() or candidate.is_symlink()
                    or candidate.stat().st_size > 2_000_000
                    or digest(_read(candidate)) != row["result_digest"]):
                raise ValueError("已接受 Worker 證據遺失或被改寫：" + ident)
    return state, snap


@exclusive_ledger
def renew_probe(root: Path, submitted: dict) -> dict:
    """Keep accepted evidence when Codex must be re-probed between batches."""
    state = _read(root / LEDGER)
    if not state.get("multi_agent_enabled"):
        raise ValueError("尚未核可多代理的審查不能透過續期跳過初次試跑")
    if state.get("integration") is not None or any(
            x["status"] in ("running", "followup_running") for x in state["tasks"].values()):
        raise ValueError("存在執行中的工作或主代理整合窗口，禁止更新 Probe")
    snap, _, _ = _snapshot(root)
    if (state["snapshot_fingerprint"] != _fingerprint(snap)
            or state["git_state"] != _git_state(root)
            or state["report_guard"] != protected_report_digest(root)):
        raise ValueError("續期時來源或正式報告有異動")
    previous = _read(root / PROBE)
    if state["probe_digest"] != digest(previous):
        raise ValueError("目前 Probe 與 Ledger 不一致；不能繞過異常版本")
    second_path = root / ANALYSIS / "multi-agent/second-pass-ledger.json"
    secondary = _read(second_path) if second_path.exists() else None
    if secondary and (secondary["probe_digest"] != digest(previous)
                      or any(x["status"] == "running" for x in secondary["tasks"].values())):
        raise ValueError("第二輪仍有執行中任務或 Probe 不一致")
    record_probe(root, submitted)
    new_probe = _read(root / PROBE)
    errs = probe_errors(root, new_probe)
    if errs:
        _write(root / PROBE, previous)
        raise ValueError("新 Probe 未完成真正能力試跑：" + "；".join(errs))
    state["probe_digest"] = digest(new_probe)
    state.setdefault("probe_renewals", []).append({
        "old_digest": digest(previous), "new_digest": digest(new_probe),
        "trace_sha256": new_probe["trace_sha256"], "verified_at": new_probe["verified_at"]})
    _write(root / LEDGER, state)
    if secondary:
        secondary["probe_digest"] = state["probe_digest"]
        secondary.setdefault("probe_renewals", []).append(state["probe_renewals"][-1])
        _write(second_path, secondary)
    return {"renewed": True, "accepted_task_count": sum(
            x["status"] == "completed" for x in state["tasks"].values()),
            "source_snapshot_unchanged": True}


@exclusive_ledger
def begin_integration(root: Path) -> dict:
    """Freeze worker activity before authoritative main-agent Stage/Integrate."""
    state, _ = _active(root)
    if any(row["status"] in ("running", "followup_running") for row in state["tasks"].values()):
        raise ValueError("仍有執行中的 Worker，不得進入主代理正式整合窗口")
    second_path = root / ANALYSIS / "multi-agent/second-pass-ledger.json"
    if second_path.exists() and any(x["status"] == "running"
                                    for x in _read(second_path)["tasks"].values()):
        raise ValueError("第二輪仍有執行中的 Worker，不可開啟整合窗口")
    from evidence_integrity import errors
    integrity_errors = errors(root)
    if integrity_errors:
        raise ValueError("正式交易完整性不符：" + "；".join(integrity_errors[:4]))
    manifest = _read(root / MANIFEST)
    if not isinstance(manifest.get("sequence"), int) or not isinstance(manifest.get("head"), str):
        raise ValueError("缺少有效 Manifest，禁止放行主代理整合")
    state["integration"] = {
        "before": state["report_guard"], "sequence": manifest["sequence"],
        "head": manifest["head"], "started_at": time.time()}
    _write(root / LEDGER, state)
    return {"integration_open": True, "manifest_sequence": manifest["sequence"],
            "warning": "整合窗口內僅允許主代理執行正式 Stage/Integrate，子代理不得讀寫"}


@exclusive_ledger
def commit_integration(root: Path) -> dict:
    """Re-seal verified main-agent transaction without trusting arbitrary edits."""
    state = _read(root / LEDGER)
    integration = state.get("integration")
    if not isinstance(integration, dict):
        raise ValueError("沒有已授權的主代理整合窗口")
    if any(row["status"] in ("running", "followup_running") for row in state["tasks"].values()):
        raise ValueError("Worker 仍在執行，不得重封存")
    snapshot, _, _ = _snapshot(root)
    if (state["snapshot_fingerprint"] != _fingerprint(snapshot)
            or state["git_state"] != _git_state(root)):
        raise ValueError("主代理整合期間原始碼或 Git 狀態改變")
    probe = _read(root / PROBE) if (root / PROBE).exists() else {}
    if state.get("probe_digest") != digest(probe):
        raise ValueError("整合期間 Probe 已異動，拒絕重封存")
    from evidence_integrity import errors
    problems = errors(root)
    if problems:
        raise ValueError("正式 Manifest／Journal 驗證不通過：" + "；".join(problems[:4]))
    manifest = _read(root / MANIFEST)
    if (type(manifest.get("sequence")) is not int
            or manifest["sequence"] <= integration["sequence"]
            or manifest.get("head") == integration["head"]):
        raise ValueError("缺少新的有效 Stage/Integrate 交易，不得默認合法變更")
    # At this point the official journal has independently authenticated all
    # authoritative tracked files. The coordinator does not write them.
    newer = protected_report_digest(root)
    secondary_path = root / ANALYSIS / "multi-agent/second-pass-ledger.json"
    if secondary_path.exists():
        secondary = _read(secondary_path)
        if (secondary.get("snapshot_fingerprint") != state["snapshot_fingerprint"]
                or secondary.get("report_guard") != integration["before"]
                or any(x.get("status") == "running" for x in secondary["tasks"].values())):
            raise ValueError("第二輪仍有 running 工作或報告指紋不同步")
    state["report_guard"] = newer
    state["integration"] = None
    state.setdefault("integration_history", []).append({
        "sequence": manifest["sequence"], "manifest_head": manifest["head"],
        "before": integration["before"], "after": newer})
    _write(root / LEDGER, state)
    return {"integration_closed": True, "manifest_sequence": manifest["sequence"],
            "source_revision_unchanged": True, "official_review_completed": False}


@exclusive_ledger
def claim(root: Path, task_id: str, *, agent_id: str | None = None) -> dict:
    state, _ = _active(root)
    task = _claim_locked(root, state, task_id, agent_id)
    _write(root / LEDGER, state)
    return task


@exclusive_ledger
def claim_batch(root: Path, assignments: list[dict]) -> dict:
    """One full snapshot check and one atomic ledger write for N parallel tasks."""
    state, _ = _active(root)
    if (not isinstance(assignments, list) or not assignments
            or len(assignments) > state["workers"]):
        raise ValueError("批次派工數量必須介於 1 至 workers 上限")
    if any(not isinstance(item, dict) or set(item) != {"task_id", "agent_id"}
           for item in assignments):
        raise ValueError("批次派工必須包含 task_id 及 agent_id")
    if (len(set(x["task_id"] for x in assignments)) != len(assignments)
            or len(set(x["agent_id"] for x in assignments)) != len(assignments)):
        raise ValueError("派工 task 或 agent_instance_id 重複")
    results = [_claim_locked(root, state, x["task_id"], x["agent_id"])
               for x in assignments]
    _write(root / LEDGER, state)
    return {"claimed": results, "workers": state["workers"],
            "note": "已使用同一個來源快照驗證及單次原子更新，請實際平行派工"}


def _claim_locked(root: Path, state: dict, task_id: str, agent_id: str) -> dict:
    if not state.get("multi_agent_enabled"):
        raise ValueError("未通過強制唯讀能力試跑，禁止使用多代理 claim，請走單代理流程")
    row = state["tasks"].get(task_id)
    if row is None:
        raise ValueError("未知 task_id")
    if row["status"] not in {"pending", "failed"} or row["attempts"] >= RETRY_LIMIT:
        raise ValueError("此分片不可重複派發；需主代理改為單代理調查")
    running = [r for r in state["tasks"].values() if r["status"] == "running"]
    if len(running) >= state["workers"]:
        raise ValueError("已達 workers 同時執行上限，應等待既有 Worker")
    if any(r["task"]["worker_id"] == row["task"]["worker_id"] for r in running):
        raise ValueError("此 worker slot 正在執行另一個分片")
    maximum = int(state["config"]["budget_tokens"] * 0.8)
    reserved = sum(x["task"]["estimated_tokens"] for x in running)
    if state.get("window_charged", 0) + reserved + row["task"]["estimated_tokens"] > maximum:
        raise ValueError("Token 預估與實測保守計費已達本輪 80% 預算，禁止超額派工")
    if not isinstance(agent_id, str) or not re.fullmatch(r"[a-zA-Z0-9_.:-]{8,128}", agent_id):
        raise ValueError("必須提供本次執行器可追溯的獨立 agent_instance_id")
    if any(r["status"] == "running" and r.get("agent_instance_id") == agent_id
           for r in state["tasks"].values()):
        raise ValueError("同一執行器 instance 不得同時領取兩個分片")
    task = row["task"]
    visible, expected = challenges_for(root, [x["path"] for x in task["assigned_paths"]])
    for part in task["assigned_paths"]:
        part["challenge_lines"] = visible[part["path"]]
    task["agent_instance_id"] = agent_id
    row["challenges"] = visible  # Only line numbers, never expected hashes in ledger
    row["agent_instance_id"] = agent_id
    row["claimed_at"] = time.time()
    row["attempts"] += 1
    row["status"] = "running"
    return task




@exclusive_ledger
def fail(root: Path, task_id: str) -> dict:
    # Explicit main-agent acknowledgement of timeout or worker error.
    state, _ = _active(root)
    row = state["tasks"].get(task_id)
    if row is None or row["status"] not in ("running", "followup_running"):
        raise ValueError("只有 running／followup_running 任務可以記錄失敗")
    if row["status"] == "followup_running":
        row["status"] = "needs_main" if row["followup_round"] >= 2 else "needs_followup"
        remaining = 2 - row["followup_round"]
    else:
        row["status"] = "failed"
        remaining = RETRY_LIMIT - row["attempts"]
    _write(root / LEDGER, state)
    return {"task_id": task_id, "status": row["status"],
            "remaining_attempts": remaining,
            "fallback_required": remaining <= 0}


@exclusive_ledger
def accept(root: Path, path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2_000_000:
        raise ValueError("結果來源不可為連結或超大檔案")
    return _accept_payload(root, _read(path))


@exclusive_ledger
def accept_stdin(root: Path, raw: str) -> dict:
    """Validate a worker message before any local write."""
    if len(raw.encode("utf-8")) > 2_000_000:
        raise ValueError("Worker 資料超出限制，拒絕保存")
    if SECRET.search(raw):
        raise ValueError("Worker 資料疑似包含憑證，尚未落地即拒絕")
    return _accept_payload(root, json.loads(raw))


def _accept_payload(root: Path, result: dict) -> dict:
    state, snap = _active(root)
    if not isinstance(result, dict):
        raise ValueError("Worker 回報必須為 JSON 物件")
    task_id = result.get("task_id")
    row = state["tasks"].get(task_id)
    if row is None:
        raise ValueError("未知 task_id")
    checksum = digest(result)
    if row["status"] in ("completed", "needs_followup"):
        if row["result_digest"] == checksum:
            return {"accepted": True, "idempotent": True, "task_id": task_id}
        raise ValueError("已完成分片的內容與既有結果衝突")
    if row["status"] != "running":
        raise ValueError("必須先由主代理 claim 分片")
    challenge_hashes = {path: {str(n): proof_line_hash(root, path, n) for n in positions}
                        for path, positions in row.get("challenges", {}).items()}
    errors = validate_worker_result(root, row["task"], result, snap["source_hashes"],
                                    challenges=challenge_hashes)
    if errors or result.get("status") != "completed":
        row["status"] = "failed"
        _write(root / LEDGER, state)
        return {"accepted": False, "task_id": task_id,
                "errors": errors or ["Worker 未完成工作"],
                "remaining_attempts": RETRY_LIMIT - row["attempts"]}
    unresolved = [dict(x) for entry in result["files"]
                  for x in entry["unresolved_symbols"]]
    row["unresolved_symbols"] = unresolved
    row["status"] = "needs_followup" if unresolved else "completed"
    row["result_digest"] = checksum
    current_manifest = root / ANALYSIS / "integrity-manifest.json"
    snapshot_manifest = _read(current_manifest) if current_manifest.exists() else {}
    row["accepted_manifest_sequence"] = snapshot_manifest.get("sequence", -1)
    row["reviewed_rule_ids"] = sorted({
        rr["rule_id"] for entry in result["files"] for rr in entry["rule_states"]
        if isinstance(rr, dict) and isinstance(rr.get("rule_id"), str)
    })
    row["finding_keys"] = sorted({
        finding_key(f) for entry in result["files"] for f in entry["findings"]
    })
    state["measured_tokens"] += result["tokens_used"]
    state["window_tokens"] = state.get("window_tokens", 0) + result["tokens_used"]
    state["window_charged"] = state.get("window_charged", 0) + max(
        result["tokens_used"], row["task"]["estimated_tokens"])
    if SECRET.search(json.dumps(result, ensure_ascii=False)):
        raise ValueError("含機敏資訊的 Worker 資料不可保存")
    destination = root / ANALYSIS / "multi-agent/results" / (task_id + ".json")
    if destination.exists():
        raise ValueError("已存在不同的已接受 Worker 結果，不可覆寫")
    _write(destination, result)
    row["result_path"] = str(destination.relative_to(root))
    _write(root / LEDGER, state)
    return {"accepted": True, "task_id": task_id,
            "needs_followup": bool(row["unresolved_symbols"]),
            "finding_keys": row["finding_keys"],
            "notice": "僅代表 Worker 格式、範圍和來源定位可驗證；主代理仍須重讀所有 Finding 與正式 Stage/Integrate"}


@exclusive_ledger
def followup(root: Path, task_id: str, *, agent_id: str) -> dict:
    state, snap = _active(root)
    row = state["tasks"].get(task_id)
    if row is None or row["status"] != "needs_followup":
        raise ValueError("只有具未解跨檔符號的已接受分片才能補派")
    if row["followup_round"] >= 2:
        raise ValueError("跨分片最多補派兩輪，改由主代理親自追查")
    if not isinstance(agent_id, str) or not re.fullmatch(r"[a-zA-Z0-9_.:-]{8,128}", agent_id):
        raise ValueError("補查須指定實際 agent_instance_id")
    if sum(x["status"] in ("running", "followup_running") for x in state["tasks"].values()) >= state["workers"]:
        raise ValueError("已達子代理併發上限")
    remaining = int(state["config"]["budget_tokens"] * 0.8) - state.get("window_charged", 0)
    reserved = sum(min(max(x["task"]["estimated_tokens"] // 4, 512), 5000)
                   for x in state["tasks"].values() if x["status"] == "followup_running")
    estimate = min(max(row["task"]["estimated_tokens"] // 4, 512), 5000)
    if estimate + reserved > remaining:
        raise ValueError("跨分片補查已達本批保守 Token 預算")
    row["followup_estimated_tokens"] = estimate
    round_number = row["followup_round"] + 1
    row["status"] = "followup_running"
    row["followup_round"] = round_number
    row["followup_agent"] = agent_id
    row["claimed_at"] = time.time()
    _write(root / LEDGER, state)
    return {"task_id": task_id, "round": round_number, "agent_instance_id": agent_id,
            "snapshot_fingerprint": state["snapshot_fingerprint"],
            "unresolved_symbols": row["unresolved_symbols"],
            "instruction": "只回報可驗證的跨檔實際來源定位；完整證據交主代理核對，不得修改審查資料"}


@exclusive_ledger
def accept_followup(root: Path, path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2_000_000:
        raise ValueError("補查結果路徑不安全")
    return _accept_followup_payload(root, _read(path))


@exclusive_ledger
def accept_followup_stdin(root: Path, raw: str) -> dict:
    if len(raw.encode("utf-8")) > 2_000_000:
        raise ValueError("跨檔補查資料過大，尚未落地即拒絕")
    if SECRET.search(raw):
        raise ValueError("跨檔補查疑似包含機敏資訊，尚未落地即拒絕")
    return _accept_followup_payload(root, json.loads(raw))


def _accept_followup_payload(root: Path, data: dict) -> dict:
    state, snap = _active(root)
    if not isinstance(data, dict):
        raise ValueError("跨檔補查回報必須為 JSON 物件")
    row = state["tasks"].get(data.get("task_id"))
    if (row is None or row["status"] != "followup_running"
            or data.get("round") != row["followup_round"]
            or data.get("agent_instance_id") != row["followup_agent"]
            or data.get("snapshot_fingerprint") != state["snapshot_fingerprint"]):
        raise ValueError("補查結果與執行中任務或快照不符")
    if set(data) not in (
            {"task_id", "round", "agent_instance_id", "snapshot_fingerprint", "resolved"},
            {"task_id", "round", "agent_instance_id", "snapshot_fingerprint", "resolved", "tokens_used"}):
        raise ValueError("補查結果存在未授權欄位")
    used = data.get("tokens_used", 0)
    if type(used) is not int or used < 0:
        raise ValueError("跨分片 Token 必須為非負實測數值")
    resolved = data["resolved"]
    if not isinstance(resolved, list):
        raise ValueError("補查結果必須是陣列")
    if SECRET.search(json.dumps(data, ensure_ascii=False)):
        raise ValueError("補查結果包含疑似機敏資訊")
    index = _read(root / INDEX)
    unresolved_ids = {(x["path"], x["name"], x["line_start"]) for x in row["unresolved_symbols"]}
    seen = set()
    for item in resolved:
        if not isinstance(item, dict) or set(item) != {"path", "name", "line_start", "evidence"}:
            raise ValueError("補查紀錄欄位不完整")
        ident = (item["path"], item["name"], item["line_start"])
        if ident not in unresolved_ids or ident in seen:
            raise ValueError("補查嘗試核銷未分配或重複符號")
        seen.add(ident)
        proof = item["evidence"]
        if not isinstance(proof, dict) or set(proof) != {"path", "line_start", "line_end", "line_hash", "summary"}:
            raise ValueError("補查控制鏈來源證據不完整")
        target = proof.get("path")
        if not isinstance(target, str) or target not in snap["source_hashes"]:
            raise ValueError("補查控制鏈不在快照中")
        from source_reader import read_source_text
        source_lines = read_source_text(root / target)[0].splitlines()
        if (type(proof.get("line_start")) is not int
                or type(proof.get("line_end")) is not int
                or proof["line_start"] < 1 or proof["line_end"] < proof["line_start"]
                or proof["line_end"] > len(source_lines)
                or proof.get("line_hash") != proof_line_hash(root, target, proof["line_start"])
                or not isinstance(proof.get("summary"), str)
                or len(proof["summary"].strip()) < 20):
            raise ValueError("補查來源行 SHA256 或說明不可信")
        hints = (index.get("cross_file_call_hints") or {}).get(item["path"], [])
        if not any(
                isinstance(h, dict) and h.get("called_method") == item["name"]
                and h.get("caller_line") == item["line_start"]
                and any(isinstance(candidate, dict)
                        and candidate.get("path") == target
                        for candidate in h.get("possible_targets", []))
                for h in hints):
            raise ValueError("補查目標與結構索引中的跨檔呼叫候選不一致")
    row.setdefault("followup_candidates", []).extend(resolved)
    # Workers provide candidates only. Main agent must close with authoritative
    # transaction and verified callsite; never turn a candidate into completed.
    row["status"] = ("needs_main" if seen or row["followup_round"] >= 2
                     else "needs_followup")
    state["measured_tokens"] += used
    state["window_tokens"] = state.get("window_tokens", 0) + used
    state["window_charged"] = state.get("window_charged", 0) + max(
        used, row.get("followup_estimated_tokens", 512))
    row.setdefault("followup_result_digests", []).append(digest(data))
    _write(root / LEDGER, state)
    return {"task_id": data["task_id"], "status": row["status"],
            "remaining_symbols": len(row["unresolved_symbols"]),
            "main_agent_verification_required": True}


@exclusive_ledger
def resolve_main(root: Path, task_id: str, evidence_path: Path) -> dict:
    """Do not clear needs_main merely by editing a status flag."""
    state, snap = _active(root)
    row = state["tasks"].get(task_id)
    if row is None or row["status"] not in ("needs_main", "needs_followup"):
        raise ValueError("僅允許主代理結案未解符號")
    if evidence_path.is_symlink() or not evidence_path.is_file() or evidence_path.stat().st_size > 2_000_000:
        raise ValueError("主代理結案證據不可為 symlink 或過大檔案")
    document = _read(evidence_path)
    if not isinstance(document, dict) or set(document) != {"task_id", "resolved", "manifest_head"}:
        raise ValueError("主代理結案證據欄位不完整")
    if SECRET.search(json.dumps(document, ensure_ascii=False)):
        raise ValueError("主代理結案證據含疑似機敏資訊")
    from evidence_integrity import errors as integrity_errors
    if integrity_errors(root):
        raise ValueError("正式審查資料完整性尚未通過驗證")
    manifest = _read(root / MANIFEST)
    if not isinstance(manifest, dict) or document["manifest_head"] != manifest.get("head"):
        raise ValueError("結案證據未綁定有效正式審查 Manifest")
    if (type(manifest.get("sequence")) is not int
            or manifest["sequence"] <= row.get("accepted_manifest_sequence", -1)):
        raise ValueError("結案前必須產生晚於 Worker 收件的正式主代理交易")
    if not isinstance(document["resolved"], list):
        raise ValueError("resolved 必須為陣列")
    expected = {(x["path"], x["name"], x["line_start"]) for x in row["unresolved_symbols"]}
    observed: set[tuple] = set()
    index = _read(root / INDEX)
    for item in document["resolved"]:
        if not isinstance(item, dict) or set(item) != {
                "path", "name", "line_start", "target_path", "target_line",
                "target_line_hash", "reason"}:
            raise ValueError("未解符號結案欄位不符合契約")
        ident = (item.get("path"), item.get("name"), item.get("line_start"))
        if ident not in expected or ident in observed:
            raise ValueError("未解符號缺失、重複或不屬於本批")
        observed.add(ident)
        target = item["target_path"]
        line = item["target_line"]
        if (not isinstance(target, str) or target not in snap["source_hashes"]
                or type(line) is not int or line < 1
                or item["target_line_hash"] != proof_line_hash(root, target, line)
                or not isinstance(item["reason"], str) or len(item["reason"].strip()) < 35):
            raise ValueError("主代理證據沒有有效的目標行及 SHA256")
        # Match at least one indexed cross-file candidate; this remains a
        # candidate, so the main agent must separately verify actual call behavior.
        hints = (index.get("cross_file_call_hints") or {}).get(item["path"], [])
        if not any(
            isinstance(h, dict)
            and h.get("called_method") == item["name"]
            and h.get("caller_line") == item["line_start"]
            and any(isinstance(x, dict) and x.get("path") == target
                    for x in h.get("possible_targets", []))
            for h in hints
        ):
            raise ValueError("未能在可信結構索引核對呼叫點與目標符號，禁止自動核銷")
    if observed != expected:
        raise ValueError("仍有未核銷跨檔符號，不得完成本分片")
    row["unresolved_symbols"] = []
    row["status"] = "completed"
    row["main_resolution_digest"] = digest(document)
    row["main_manifest_head"] = manifest["head"]
    _write(root / LEDGER, state)
    return {"task_id": task_id, "status": "completed",
            "formal_security_verdict": False, "main_resolution_recorded": True}


@exclusive_ledger
def renew_budget(root: Path) -> dict:
    # Main agent must checkpoint and explicitly start the next budget window.
    state, _ = _active(root)
    if any(row["status"] in ("running", "followup_running") for row in state["tasks"].values()):
        raise ValueError("仍有執行中分片，不能在批次中途重設預算")
    limit = int(state["config"]["budget_tokens"] * 0.8)
    charge = state.get("window_charged", 0)
    pending = [row["task"]["estimated_tokens"] for row in state["tasks"].values()
               if row["status"] in ("pending", "failed") and row["attempts"] < RETRY_LIMIT]
    pending += [min(max(row["task"]["estimated_tokens"] // 4, 512), 5000)
                for row in state["tasks"].values()
                if row["status"] == "needs_followup" and row["followup_round"] < 2]
    if charge < limit and (not pending or any(cost <= limit - charge for cost in pending)):
        raise ValueError("目前仍有可執行的分片，無須續開 Token 窗口")
    if pending and min(pending) > limit:
        raise ValueError("單一分片超過窗口上限，須重新分片或由主代理處理")
    state["budget_window"] = state.get("budget_window", 1) + 1
    state["window_tokens"] = 0
    state["window_charged"] = 0
    _write(root / LEDGER, state)
    return {"budget_window": state["budget_window"],
            "measured_tokens_total": state["measured_tokens"],
            "formal_review_completed": False}


def summary(root: Path) -> dict:
    state, snap = _active(root)
    done = [row["task"] for row in state["tasks"].values()
            if row["status"] == "completed"]
    covered = [f["path"] for row in done for f in row["assigned_paths"]]
    expected = set(snap["source_hashes"])
    missing = sorted(expected - set(covered))
    duplicate = len(covered) != len(set(covered))
    unresolved = [ident for ident, row in state["tasks"].items()
                  if row["status"] != "completed"]
    return {"multi_agent_enabled": state["multi_agent_enabled"],
            "workers": state["workers"], "task_counts": {
                value: sum(x["status"] == value for x in state["tasks"].values())
                for value in ("pending", "running", "failed", "followup_running", "needs_followup", "needs_main", "completed")},
            "missing_source_paths": missing, "duplicate_primary_ownership": duplicate,
            "unresolved_tasks": unresolved,
            "running_tasks": {ident: {"claimed_at": row.get("claimed_at"),
                                      "agent_instance_id": row.get("agent_instance_id")}
                              for ident, row in state["tasks"].items() if row["status"] in ("running", "followup_running")},
            "measured_tokens": state["measured_tokens"],
            "unresolved_symbol_count": sum(len(r.get("unresolved_symbols", []))
                                           for r in state["tasks"].values()),
            "window_tokens": state.get("window_tokens", 0),
            "window_charged": state.get("window_charged", 0),
            "budget_window": state.get("budget_window", 1),
            "work_results_accepted": not missing and not duplicate and not unresolved,
            "formal_review_completed": False,
            "notice": "Worker 自述覆蓋不等於正式逐檔審查；仍需 70 規則、跨檔閉包、第二輪及正式守門。"}


def blind_tasks(root: Path) -> dict:
    """Return evidence-only second-pass prompts; never expose first-pass verdicts."""
    from second_pass_layers import worklist
    work = worklist(root)
    if not work.get("ready"):
        raise ValueError("第二輪尚未固定第一輪 Baseline")
    allowed = {"rule_id", "evidence_anchors", "candidate_paths", "needs_new_anchor",
               "path", "risk_signals"}
    def sanitized(items):
        if not isinstance(items, list):
            return []
        return [{k: v for k, v in item.items() if k in allowed}
                for item in items if isinstance(item, dict)]
    return {"phase": "blind_challenge", "rule_tasks": sanitized(work.get("rule_tasks")),
            "sample_tasks": sanitized(work.get("sample_tasks")),
            "task_note": "獨立提出可反駁假設與真實來源行號；不得先讀取第一輪 verdict、assessment 判定或 baseline digest；主代理負責矛盾裁決",
            "formal_second_pass_completed": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=Path.cwd())
    mode = parser.add_mutually_exclusive_group(required=True)
    for name in ("probe-template", "record-probe", "renew-probe", "plan", "begin-integration", "commit-integration", "resolve-main", "next", "claim", "claim-batch", "fail", "followup", "accept-followup", "accept-followup-stdin", "renew-budget", "accept", "accept-stdin",
                 "status", "blind-tasks"):
        mode.add_argument("--" + name, action="store_true")
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--task-id")
    parser.add_argument("--agent-id")
    parser.add_argument("--assignments", type=Path)
    parser.add_argument("--result", type=Path)
    parser.add_argument("--max-agents", type=int, default=3)
    parser.add_argument("--replan", action="store_true")
    parser.add_argument("--budget-tokens", type=int, default=96000)
    parser.add_argument("--task-tokens", type=int, default=12000)
    args = parser.parse_args()
    root = args.target.resolve()
    try:
        if args.probe_template:
            answer = probe_template()
        elif args.record_probe:
            if args.evidence is None:
                raise ValueError("--record-probe 必須指定 --evidence")
            answer = record_probe(root, _read(args.evidence))
        elif args.renew_probe:
            if args.evidence is None:
                raise ValueError("--renew-probe 需提供新試跑紀錄 --evidence")
            answer = renew_probe(root, _read(args.evidence))
        elif args.plan:
            state = plan(root, max_agents=args.max_agents,
                         budget_tokens=args.budget_tokens, task_tokens=args.task_tokens,
                         replan=args.replan)
            answer = {"multi_agent_enabled": state["multi_agent_enabled"],
                      "workers": state["workers"],
                      "fallback_reason": state["fallback_reason"],
                      "task_count": len(state["tasks"]), "formal_review_completed": False}
        elif args.resolve_main:
            if not args.task_id or args.evidence is None:
                raise ValueError("--resolve-main 需要 --task-id 與 --evidence")
            answer = resolve_main(root, args.task_id, args.evidence)
        elif args.begin_integration:
            answer = begin_integration(root)
        elif args.commit_integration:
            answer = commit_integration(root)
        elif args.next:
            state, _ = _active(root)
            answer = {"tasks": [row["task"] for row in state["tasks"].values()
                                if row["status"] in ("pending", "failed")
                                and row["attempts"] < RETRY_LIMIT],
                      "running": {key: {"claimed_at": row.get("claimed_at"),
                                         "agent_instance_id": row.get("agent_instance_id"),
                                         "status": row["status"]}
                                  for key, row in state["tasks"].items()
                                  if row["status"] in ("running", "followup_running")},
                      "unresolved_followups": [key for key, row in state["tasks"].items()
                                               if row["status"] in ("needs_followup", "needs_main")],
                      "formal_review_completed": False}
        elif args.claim_batch:
            if args.assignments is None or args.assignments.is_symlink():
                raise ValueError("--claim-batch 必須指定受控 --assignments JSON 路徑")
            payload = json.loads(args.assignments.read_text(encoding="utf-8"))
            answer = claim_batch(root, payload)
        elif args.claim:
            if not args.task_id:
                raise ValueError("--claim 必須指定 --task-id")
            answer = claim(root, args.task_id, agent_id=args.agent_id)
        elif args.fail:
            if not args.task_id:
                raise ValueError("--fail 必須指定 --task-id")
            answer = fail(root, args.task_id)
        elif args.followup:
            if not args.task_id or not args.agent_id:
                raise ValueError("--followup 必須指定 --task-id 與 --agent-id")
            answer = followup(root, args.task_id, agent_id=args.agent_id)
        elif args.accept_followup_stdin:
            answer = accept_followup_stdin(root, sys.stdin.read(2_000_001))
        elif args.accept_followup:
            if args.result is None:
                raise ValueError("--accept-followup 必須指定 --result")
            answer = accept_followup(root, args.result)
        elif args.renew_budget:
            answer = renew_budget(root)
        elif args.accept_stdin:
            answer = accept_stdin(root, sys.stdin.read(2_000_001))
        elif args.accept:
            if args.result is None:
                raise ValueError("--accept 必須指定 --result")
            answer = accept(root, args.result)
        elif args.status:
            answer = summary(root)
        else:
            answer = blind_tasks(root)
        print(json.dumps(answer, ensure_ascii=False, separators=(",", ":")))
        return 0 if not (args.accept and not answer.get("accepted")) else 2
    except (OSError, ValueError, KeyError, TypeError, UnicodeError,
            json.JSONDecodeError) as exc:
        print("ERROR: 多代理守門拒絕操作：" + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
