#!/usr/bin/env python3
"""多代理能力試跑、分片計畫與整合交易；僅主代理呼叫，不建立或啟動子代理。"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

from multi_agent_contract import SECRET, VERSION, digest
from multi_agent_guard import CHECKS, exclusive_ledger, probe_errors, protected_report_digest, runtime_binding, sha
from evidence_integrity import MANIFEST
import multi_agent_ledger as ml


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
    ml._write(root / ml.PROBE, safe)
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
                        "estimated_tokens": estimate, "risk": bool(ml.HIGH_RISK.search(path))})
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
    fp = ml._fingerprint(snap)
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
    snap, index, _ = ml._snapshot(root)
    try:
        probe = ml._read(root / ml.PROBE)
    except FileNotFoundError:
        probe = {}
    # Do not claim that an in-chat declaration enforces a sandbox.
    # Gitless targets still have an exact source inventory and SHA256 snapshot.
    # Only the native executor + forced read-only P0 probe determines availability.
    enabled = not probe_errors(root, probe)
    built = _build_tasks(root, snap, index, max_agents=max_agents,
                         budget_tokens=budget_tokens, task_tokens=task_tokens, probe_ok=enabled)
    current = root / ml.LEDGER
    if current.exists():
        prior = ml._read(current)
        compatible = (prior.get("snapshot_fingerprint") == ml._fingerprint(snap)
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
        history = root / ml.ANALYSIS / "multi-agent/history"
        history.mkdir(parents=True, exist_ok=True)
        import os
        archive = history / ("ledger-" + digest(prior)[:24] + ".json")
        if archive.exists():
            raise ValueError("歷史 Ledger 已存在，拒絕覆蓋")
        os.replace(current, archive)
    state = {"schema_version": VERSION, "snapshot_fingerprint": ml._fingerprint(snap),
             "probe_digest": digest(probe),
             "report_guard": protected_report_digest(root),
             "integration": None,
             "git_state": ml._git_state(root), "multi_agent_enabled": enabled,
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
    ml._write(current, state)
    return state


@exclusive_ledger
def renew_probe(root: Path, submitted: dict) -> dict:
    """Keep accepted evidence when Codex must be re-probed between batches."""
    state = ml._read(root / ml.LEDGER)
    if not state.get("multi_agent_enabled"):
        raise ValueError("尚未核可多代理的審查不能透過續期跳過初次試跑")
    if state.get("integration") is not None or any(
            x["status"] in ("running", "followup_running") for x in state["tasks"].values()):
        raise ValueError("存在執行中的工作或主代理整合窗口，禁止更新 Probe")
    snap, _, _ = ml._snapshot(root)
    if (state["snapshot_fingerprint"] != ml._fingerprint(snap)
            or state["git_state"] != ml._git_state(root)
            or state["report_guard"] != protected_report_digest(root)):
        raise ValueError("續期時來源或正式報告有異動")
    previous = ml._read(root / ml.PROBE)
    if state["probe_digest"] != digest(previous):
        raise ValueError("目前 Probe 與 Ledger 不一致；不能繞過異常版本")
    second_path = root / ml.ANALYSIS / "multi-agent/second-pass-ledger.json"
    secondary = ml._read(second_path) if second_path.exists() else None
    if secondary and (secondary["probe_digest"] != digest(previous)
                      or any(x["status"] == "running" for x in secondary["tasks"].values())):
        raise ValueError("第二輪仍有執行中任務或 Probe 不一致")
    record_probe(root, submitted)
    new_probe = ml._read(root / ml.PROBE)
    errs = probe_errors(root, new_probe)
    if errs:
        ml._write(root / ml.PROBE, previous)
        raise ValueError("新 Probe 未完成真正能力試跑：" + "；".join(errs))
    state["probe_digest"] = digest(new_probe)
    state.setdefault("probe_renewals", []).append({
        "old_digest": digest(previous), "new_digest": digest(new_probe),
        "trace_sha256": new_probe["trace_sha256"], "verified_at": new_probe["verified_at"]})
    ml._write(root / ml.LEDGER, state)
    if secondary:
        secondary["probe_digest"] = state["probe_digest"]
        secondary.setdefault("probe_renewals", []).append(state["probe_renewals"][-1])
        ml._write(second_path, secondary)
    return {"renewed": True, "accepted_task_count": sum(
            x["status"] == "completed" for x in state["tasks"].values()),
            "source_snapshot_unchanged": True}


@exclusive_ledger
def begin_integration(root: Path) -> dict:
    """Freeze worker activity before authoritative main-agent Stage/Integrate."""
    state, _ = ml._active(root)
    if any(row["status"] in ("running", "followup_running") for row in state["tasks"].values()):
        raise ValueError("仍有執行中的 Worker，不得進入主代理正式整合窗口")
    second_path = root / ml.ANALYSIS / "multi-agent/second-pass-ledger.json"
    if second_path.exists() and any(x["status"] == "running"
                                    for x in ml._read(second_path)["tasks"].values()):
        raise ValueError("第二輪仍有執行中的 Worker，不可開啟整合窗口")
    from evidence_integrity import errors
    integrity_errors = errors(root)
    if integrity_errors:
        raise ValueError("正式交易完整性不符：" + "；".join(integrity_errors[:4]))
    manifest = ml._read(root / MANIFEST)
    if not isinstance(manifest.get("sequence"), int) or not isinstance(manifest.get("head"), str):
        raise ValueError("缺少有效 Manifest，禁止放行主代理整合")
    state["integration"] = {
        "before": state["report_guard"], "sequence": manifest["sequence"],
        "head": manifest["head"], "started_at": time.time()}
    ml._write(root / ml.LEDGER, state)
    return {"integration_open": True, "manifest_sequence": manifest["sequence"],
            "warning": "整合窗口內僅允許主代理執行正式 Stage/Integrate，子代理不得讀寫"}


@exclusive_ledger
def commit_integration(root: Path) -> dict:
    """Re-seal verified main-agent transaction without trusting arbitrary edits."""
    state = ml._read(root / ml.LEDGER)
    integration = state.get("integration")
    if not isinstance(integration, dict):
        raise ValueError("沒有已授權的主代理整合窗口")
    if any(row["status"] in ("running", "followup_running") for row in state["tasks"].values()):
        raise ValueError("Worker 仍在執行，不得重封存")
    snapshot, _, _ = ml._snapshot(root)
    if (state["snapshot_fingerprint"] != ml._fingerprint(snapshot)
            or state["git_state"] != ml._git_state(root)):
        raise ValueError("主代理整合期間原始碼或 Git 狀態改變")
    probe = ml._read(root / ml.PROBE) if (root / ml.PROBE).exists() else {}
    if state.get("probe_digest") != digest(probe):
        raise ValueError("整合期間 Probe 已異動，拒絕重封存")
    from evidence_integrity import errors
    problems = errors(root)
    if problems:
        raise ValueError("正式 Manifest／Journal 驗證不通過：" + "；".join(problems[:4]))
    manifest = ml._read(root / MANIFEST)
    if (type(manifest.get("sequence")) is not int
            or manifest["sequence"] <= integration["sequence"]
            or manifest.get("head") == integration["head"]):
        raise ValueError("缺少新的有效 Stage/Integrate 交易，不得默認合法變更")
    # At this point the official journal has independently authenticated all
    # authoritative tracked files. The coordinator does not write them.
    newer = protected_report_digest(root)
    secondary_path = root / ml.ANALYSIS / "multi-agent/second-pass-ledger.json"
    if secondary_path.exists():
        secondary = ml._read(secondary_path)
        if (secondary.get("snapshot_fingerprint") != state["snapshot_fingerprint"]
                or secondary.get("report_guard") != integration["before"]
                or any(x.get("status") == "running" for x in secondary["tasks"].values())):
            raise ValueError("第二輪仍有 running 工作或報告指紋不同步")
    state["report_guard"] = newer
    state["integration"] = None
    state.setdefault("integration_history", []).append({
        "sequence": manifest["sequence"], "manifest_head": manifest["head"],
        "before": integration["before"], "after": newer})
    ml._write(root / ml.LEDGER, state)
    return {"integration_closed": True, "manifest_sequence": manifest["sequence"],
            "source_revision_unchanged": True, "official_review_completed": False}
