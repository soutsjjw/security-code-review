#!/usr/bin/env python3
"""Main-agent-only multi-agent ledger. Does not spawn agents or modify assessment."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

from multi_agent_contract import VERSION, digest, validate_worker_result, finding_key
from source_reader import source_digest
from source_coverage import expected_paths
from scope_inventory import relative_path

ANALYSIS = Path("reports/security-code-review/analysis")
LEDGER = ANALYSIS / "multi-agent/ledger.json"
PROBE = ANALYSIS / "multi-agent/capability-probe.json"
SNAPSHOT = ANALYSIS / "review-snapshot.json"
INDEX = ANALYSIS / "structure-index.json"
REPORT = Path("reports/security-code-review")
HIGH_RISK = re.compile(r"auth|identity|session|credential|permission|access|"
                       r"controller|endpoint|request|input|upload|serializ|"
                       r"deserializ|middleware|token|password|config", re.I)
CHECKS = ("parallel_dispatch", "independent_context", "single_layer",
          "enforced_read_only", "structured_result", "failure_recovery")
RETRY_LIMIT = 2


def _read(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("JSON root 必須為物件")
    return data


def _write(path: Path, data: dict) -> None:
    # Main-agent-only metadata. Do not use this for assessment/Manifest/Journal.
    import os
    import uuid
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError("狀態路徑不可為符號連結")
    temp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        temp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8")
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def _git_state(root: Path) -> dict:
    head = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=False)
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
        e[3:].replace(b"\\", b"/").startswith(b"reports/security-code-review/")
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
    return snap, index, assessment


def _fingerprint(snap: dict) -> str:
    return digest({"git_revision": snap.get("git_revision"),
                   "source_hashes": snap["source_hashes"],
                   "excluded_paths": snap.get("excluded_paths", [])})


def probe_template() -> dict:
    return {"schema_version": VERSION, "codex_version": "",
            "execution_id": "", "checks": {key: False for key in CHECKS},
            "evidence_note": "必須填寫實際執行的獨立子代理試跑觀察，不得只以文件推定"}


def record_probe(root: Path, submitted: dict) -> dict:
    checks = submitted.get("checks")
    if (submitted.get("schema_version") != VERSION
            or not isinstance(checks, dict) or set(checks) != set(CHECKS)
            or any(type(x) is not bool for x in checks.values())
            or not isinstance(submitted.get("codex_version"), str)
            or not isinstance(submitted.get("execution_id"), str)
            or len(submitted["execution_id"].strip()) < 4
            or not isinstance(submitted.get("evidence_note"), str)
            or len(submitted["evidence_note"].strip()) < 30):
        raise ValueError("P0 試跑紀錄缺少實測資訊")
    # A declaration is not proof: the main agent must retain the independent
    # experiment outputs for review; this gate only refuses missing/failed checks.
    if all(checks.values()) and not submitted["codex_version"].strip():
        raise ValueError("全數核可的 P0 試跑必須填入實際 Codex 版本")
    safe = {key: submitted[key] for key in ("schema_version", "codex_version",
                                            "execution_id", "checks", "evidence_note")}
    raw = json.dumps(safe, ensure_ascii=False)
    from multi_agent_contract import SECRET
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


def plan(root: Path, *, max_agents: int = 3, budget_tokens: int = 96000,
         task_tokens: int = 12000) -> dict:
    if not 1 <= max_agents <= 8 or budget_tokens < 12000 or not 2000 <= task_tokens <= 30000:
        raise ValueError("workers/budget/task_tokens 不在允許範圍")
    snap, index, _ = _snapshot(root)
    try:
        probe = _read(root / PROBE)
    except FileNotFoundError:
        probe = {}
    # Do not claim that an in-chat declaration enforces a sandbox.
    enabled = (probe.get("verified") is True
               and all((probe.get("checks") or {}).get(k) is True for k in CHECKS)
               and _git_state(root)["head"] is not None)
    built = _build_tasks(root, snap, index, max_agents=max_agents,
                         budget_tokens=budget_tokens, task_tokens=task_tokens, probe_ok=enabled)
    current = root / LEDGER
    if current.exists():
        prior = _read(current)
        if (prior.get("snapshot_fingerprint") != _fingerprint(snap)
                or prior.get("config") != {"max_agents": max_agents, "budget_tokens": budget_tokens,
                                         "task_tokens": task_tokens}):
            raise ValueError("已有不同快照或設定的多代理 Ledger，不得默默覆寫")
        return prior
    state = {"schema_version": VERSION, "snapshot_fingerprint": _fingerprint(snap),
             "git_state": _git_state(root), "multi_agent_enabled": enabled,
             "workers": built["workers"],
             "fallback_reason": None if enabled else "P0 尚未實測核可，退回單代理",
             "config": {"max_agents": max_agents, "budget_tokens": budget_tokens,
                        "task_tokens": task_tokens},
             "estimated_total_tokens": built["estimated_tokens"], "measured_tokens": 0,
             "tasks": {key: {"task": task, "status": "pending", "attempts": 0,
                             "result_digest": None, "finding_keys": []}
                       for key, task in built["tasks"].items()}}
    _write(current, state)
    return state


def _active(root: Path) -> tuple[dict, dict]:
    state = _read(root / LEDGER)
    snap, _, _ = _snapshot(root)
    if (state.get("snapshot_fingerprint") != _fingerprint(snap)
            or state.get("git_state") != _git_state(root)):
        raise ValueError("來源或 Git 狀態異動；停用既有子代理結果並重新查證")
    return state, snap


def claim(root: Path, task_id: str) -> dict:
    state, _ = _active(root)
    row = state["tasks"].get(task_id)
    if row is None:
        raise ValueError("未知 task_id")
    if row["status"] not in {"pending", "failed"} or row["attempts"] >= RETRY_LIMIT:
        raise ValueError("此分片不可重複派發；需主代理改為單代理調查")
    if state["measured_tokens"] >= state["config"]["budget_tokens"]:
        raise ValueError("Token 已達預算，停止新增平行工作")
    row["attempts"] += 1
    row["status"] = "running"
    _write(root / LEDGER, state)
    return row["task"]


def fail(root: Path, task_id: str) -> dict:
    # Explicit main-agent acknowledgement of timeout or worker error.
    state, _ = _active(root)
    row = state["tasks"].get(task_id)
    if row is None or row["status"] != "running":
        raise ValueError("只有 running 任務可以記錄失敗")
    row["status"] = "failed"
    _write(root / LEDGER, state)
    return {"task_id": task_id, "status": "failed",
            "remaining_attempts": RETRY_LIMIT - row["attempts"],
            "fallback_required": row["attempts"] >= RETRY_LIMIT}


def accept(root: Path, path: Path) -> dict:
    state, snap = _active(root)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2_000_000:
        raise ValueError("結果來源不可為連結或超大檔案")
    result = _read(path)
    task_id = result.get("task_id")
    row = state["tasks"].get(task_id)
    if row is None:
        raise ValueError("未知 task_id")
    checksum = digest(result)
    if row["status"] == "completed":
        if row["result_digest"] == checksum:
            return {"accepted": True, "idempotent": True, "task_id": task_id}
        raise ValueError("已完成分片的內容與既有結果衝突")
    if row["status"] != "running":
        raise ValueError("必須先由主代理 claim 分片")
    errors = validate_worker_result(root, row["task"], result, snap["source_hashes"])
    if errors or result.get("status") != "completed":
        row["status"] = "failed"
        _write(root / LEDGER, state)
        return {"accepted": False, "task_id": task_id,
                "errors": errors or ["Worker 未完成工作"],
                "remaining_attempts": RETRY_LIMIT - row["attempts"]}
    row["status"] = "completed"
    row["result_digest"] = checksum
    row["finding_keys"] = sorted({
        finding_key(f) for entry in result["files"] for f in entry["findings"]
    })
    state["measured_tokens"] += result["tokens_used"]
    _write(root / LEDGER, state)
    return {"accepted": True, "task_id": task_id, "finding_keys": row["finding_keys"],
            "notice": "僅代表 Worker 格式、範圍和來源定位可驗證；主代理仍須重讀所有 Finding 與正式 Stage/Integrate"}


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
                for value in ("pending", "running", "failed", "completed")},
            "missing_source_paths": missing, "duplicate_primary_ownership": duplicate,
            "unresolved_tasks": unresolved,
            "measured_tokens": state["measured_tokens"],
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
    for name in ("probe-template", "record-probe", "plan", "next", "claim", "fail", "accept",
                 "status", "blind-tasks"):
        mode.add_argument("--" + name, action="store_true")
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--task-id")
    parser.add_argument("--result", type=Path)
    parser.add_argument("--max-agents", type=int, default=3)
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
        elif args.plan:
            state = plan(root, max_agents=args.max_agents,
                         budget_tokens=args.budget_tokens, task_tokens=args.task_tokens)
            answer = {"multi_agent_enabled": state["multi_agent_enabled"],
                      "workers": state["workers"],
                      "fallback_reason": state["fallback_reason"],
                      "task_count": len(state["tasks"]), "formal_review_completed": False}
        elif args.next:
            state, _ = _active(root)
            answer = {"tasks": [row["task"] for row in state["tasks"].values()
                                if row["status"] in ("pending", "failed")
                                and row["attempts"] < RETRY_LIMIT],
                      "formal_review_completed": False}
        elif args.claim:
            if not args.task_id:
                raise ValueError("--claim 必須指定 --task-id")
            answer = claim(root, args.task_id)
        elif args.fail:
            if not args.task_id:
                raise ValueError("--fail 必須指定 --task-id")
            answer = fail(root, args.task_id)
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
