#!/usr/bin/env python3
"""多代理分片的領取、結果驗收、追查、失敗重試與主代理裁決；僅記錄 Ledger，不修改 assessment。"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

from multi_agent_contract import SECRET, digest, validate_worker_result, finding_key
from multi_agent_guard import challenges_for, exclusive_ledger, proof_line_hash
from evidence_integrity import MANIFEST
import multi_agent_ledger as ml


@exclusive_ledger
def claim(root: Path, task_id: str, *, agent_id: str | None = None) -> dict:
    state, _ = ml._active(root)
    task = _claim_locked(root, state, task_id, agent_id)
    ml._write(root / ml.LEDGER, state)
    return task


@exclusive_ledger
def claim_batch(root: Path, assignments: list[dict]) -> dict:
    """One full snapshot check and one atomic ledger write for N parallel tasks."""
    state, _ = ml._active(root)
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
    ml._write(root / ml.LEDGER, state)
    return {"claimed": results, "workers": state["workers"],
            "note": "已使用同一個來源快照驗證及單次原子更新，請實際平行派工"}


def _claim_locked(root: Path, state: dict, task_id: str, agent_id: str) -> dict:
    if not state.get("multi_agent_enabled"):
        raise ValueError("未通過強制唯讀能力試跑，禁止使用多代理 claim，請走單代理流程")
    row = state["tasks"].get(task_id)
    if row is None:
        raise ValueError("未知 task_id")
    if row["status"] not in {"pending", "failed"} or row["attempts"] >= ml.RETRY_LIMIT:
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
    state, _ = ml._active(root)
    row = state["tasks"].get(task_id)
    if row is None or row["status"] not in ("running", "followup_running"):
        raise ValueError("只有 running／followup_running 任務可以記錄失敗")
    if row["status"] == "followup_running":
        row["status"] = "needs_main" if row["followup_round"] >= 2 else "needs_followup"
        remaining = 2 - row["followup_round"]
    else:
        row["status"] = "failed"
        remaining = ml.RETRY_LIMIT - row["attempts"]
    ml._write(root / ml.LEDGER, state)
    return {"task_id": task_id, "status": row["status"],
            "remaining_attempts": remaining,
            "fallback_required": remaining <= 0}


@exclusive_ledger
def accept(root: Path, path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2_000_000:
        raise ValueError("結果來源不可為連結或超大檔案")
    return _accept_payload(root, ml._read(path))


@exclusive_ledger
def accept_stdin(root: Path, raw: str) -> dict:
    """Validate a worker message before any local write."""
    if len(raw.encode("utf-8")) > 2_000_000:
        raise ValueError("Worker 資料超出限制，拒絕保存")
    if SECRET.search(raw):
        raise ValueError("Worker 資料疑似包含憑證，尚未落地即拒絕")
    return _accept_payload(root, json.loads(raw))


def _accept_payload(root: Path, result: dict) -> dict:
    state, snap = ml._active(root)
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
        ml._write(root / ml.LEDGER, state)
        return {"accepted": False, "task_id": task_id,
                "errors": errors or ["Worker 未完成工作"],
                "remaining_attempts": ml.RETRY_LIMIT - row["attempts"]}
    unresolved = [dict(x) for entry in result["files"]
                  for x in entry["unresolved_symbols"]]
    row["unresolved_symbols"] = unresolved
    row["status"] = "needs_followup" if unresolved else "completed"
    row["result_digest"] = checksum
    current_manifest = root / ml.ANALYSIS / "integrity-manifest.json"
    snapshot_manifest = ml._read(current_manifest) if current_manifest.exists() else {}
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
    destination = root / ml.ANALYSIS / "multi-agent/results" / (task_id + ".json")
    if destination.exists():
        raise ValueError("已存在不同的已接受 Worker 結果，不可覆寫")
    ml._write(destination, result)
    row["result_path"] = str(destination.relative_to(root))
    ml._write(root / ml.LEDGER, state)
    return {"accepted": True, "task_id": task_id,
            "needs_followup": bool(row["unresolved_symbols"]),
            "finding_keys": row["finding_keys"],
            "notice": "僅代表 Worker 格式、範圍和來源定位可驗證；主代理仍須重讀所有 Finding 與正式 Stage/Integrate"}


@exclusive_ledger
def followup(root: Path, task_id: str, *, agent_id: str) -> dict:
    state, snap = ml._active(root)
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
    ml._write(root / ml.LEDGER, state)
    return {"task_id": task_id, "round": round_number, "agent_instance_id": agent_id,
            "snapshot_fingerprint": state["snapshot_fingerprint"],
            "unresolved_symbols": row["unresolved_symbols"],
            "instruction": "只回報可驗證的跨檔實際來源定位；完整證據交主代理核對，不得修改審查資料"}


@exclusive_ledger
def accept_followup(root: Path, path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2_000_000:
        raise ValueError("補查結果路徑不安全")
    return _accept_followup_payload(root, ml._read(path))


@exclusive_ledger
def accept_followup_stdin(root: Path, raw: str) -> dict:
    if len(raw.encode("utf-8")) > 2_000_000:
        raise ValueError("跨檔補查資料過大，尚未落地即拒絕")
    if SECRET.search(raw):
        raise ValueError("跨檔補查疑似包含機敏資訊，尚未落地即拒絕")
    return _accept_followup_payload(root, json.loads(raw))


def _accept_followup_payload(root: Path, data: dict) -> dict:
    state, snap = ml._active(root)
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
    index = ml._read(root / ml.INDEX)
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
    ml._write(root / ml.LEDGER, state)
    return {"task_id": data["task_id"], "status": row["status"],
            "remaining_symbols": len(row["unresolved_symbols"]),
            "main_agent_verification_required": True}


@exclusive_ledger
def resolve_main(root: Path, task_id: str, evidence_path: Path) -> dict:
    """Do not clear needs_main merely by editing a status flag."""
    state, snap = ml._active(root)
    row = state["tasks"].get(task_id)
    if row is None or row["status"] not in ("needs_main", "needs_followup"):
        raise ValueError("僅允許主代理結案未解符號")
    if evidence_path.is_symlink() or not evidence_path.is_file() or evidence_path.stat().st_size > 2_000_000:
        raise ValueError("主代理結案證據不可為 symlink 或過大檔案")
    document = ml._read(evidence_path)
    if not isinstance(document, dict) or set(document) != {"task_id", "resolved", "manifest_head"}:
        raise ValueError("主代理結案證據欄位不完整")
    if SECRET.search(json.dumps(document, ensure_ascii=False)):
        raise ValueError("主代理結案證據含疑似機敏資訊")
    from evidence_integrity import errors as integrity_errors
    if integrity_errors(root):
        raise ValueError("正式審查資料完整性尚未通過驗證")
    manifest = ml._read(root / MANIFEST)
    if not isinstance(manifest, dict) or document["manifest_head"] != manifest.get("head"):
        raise ValueError("結案證據未綁定有效正式審查 Manifest")
    if (type(manifest.get("sequence")) is not int
            or manifest["sequence"] <= row.get("accepted_manifest_sequence", -1)):
        raise ValueError("結案前必須產生晚於 Worker 收件的正式主代理交易")
    if not isinstance(document["resolved"], list):
        raise ValueError("resolved 必須為陣列")
    expected = {(x["path"], x["name"], x["line_start"]) for x in row["unresolved_symbols"]}
    observed: set[tuple] = set()
    index = ml._read(root / ml.INDEX)
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
    ml._write(root / ml.LEDGER, state)
    return {"task_id": task_id, "status": "completed",
            "formal_security_verdict": False, "main_resolution_recorded": True}


@exclusive_ledger
def renew_budget(root: Path) -> dict:
    # Main agent must checkpoint and explicitly start the next budget window.
    state, _ = ml._active(root)
    if any(row["status"] in ("running", "followup_running") for row in state["tasks"].values()):
        raise ValueError("仍有執行中分片，不能在批次中途重設預算")
    limit = int(state["config"]["budget_tokens"] * 0.8)
    charge = state.get("window_charged", 0)
    pending = [row["task"]["estimated_tokens"] for row in state["tasks"].values()
               if row["status"] in ("pending", "failed") and row["attempts"] < ml.RETRY_LIMIT]
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
    ml._write(root / ml.LEDGER, state)
    return {"budget_window": state["budget_window"],
            "measured_tokens_total": state["measured_tokens"],
            "formal_review_completed": False}


def summary(root: Path) -> dict:
    state, snap = ml._active(root)
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
