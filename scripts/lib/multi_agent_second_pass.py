#!/usr/bin/env python3
"""Untrusted second-pass challenges with independent executor identity and no verdicts.

Main agent alone adjudicates and writes official adversarial reviews.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

from multi_agent_ledger import ANALYSIS, LEDGER, PROBE, write_ledger_json, source_snapshot, ledger_fingerprint, git_state
from multi_agent_contract import VERSION, SECRET, digest
from multi_agent_guard import (probe_errors, protected_report_digest,
                               challenges_for, proof_line_hash, exclusive_ledger)
from review_core import load_json_object

SECOND = ANALYSIS / "multi-agent/second-pass-ledger.json"
AGENT = re.compile(r"^[A-Za-z0-9_.:-]{8,128}$")
MAX_BYTES = 2_000_000


def _source_targets(task: dict, hashes: dict) -> list[str]:
    paths = {a["path"] for a in task.get("evidence_anchors", [])
             if isinstance(a, dict) and a.get("path") in hashes}
    paths.update(p for p in task.get("candidate_paths", []) if p in hashes)
    if task.get("path") in hashes:
        paths.add(task["path"])
    if not paths:
        raise ValueError("第二輪工作缺少可定位來源，必須由主代理追查")
    return sorted(paths)


@exclusive_ledger
def plan(root: Path, *, advance: bool = False) -> dict:
    from second_pass_layers import worklist
    work = worklist(root)
    if not work.get("ready"):
        raise ValueError("第一輪 Baseline 尚未固定")
    baseline = load_json_object(root / ANALYSIS / "first-pass-baseline.json")
    first = load_json_object(root / LEDGER)
    snap, _, _ = source_snapshot(root)
    probe = load_json_object(root / PROBE)
    if probe_errors(root, probe) or first.get("probe_digest") != digest(probe):
        raise ValueError("第二輪不得沿用失效的 Codex 唯讀 probe")
    if first.get("snapshot_fingerprint") != ledger_fingerprint(snap):
        raise ValueError("第一輪及第二輪來源快照不符")
    if any(x.get("status") != "completed" for x in first["tasks"].values()):
        raise ValueError("第一輪仍有未完成或未結的跨分片工作")
    owners: dict[str, set[str]] = {}
    for row in first["tasks"].values():
        agent = row.get("agent_instance_id")
        if not isinstance(agent, str) or not AGENT.fullmatch(agent):
            raise ValueError("第一輪缺少可追溯的執行緒身分，不得宣稱獨立複核")
        for rule_id in row.get("reviewed_rule_ids", []):
            owners.setdefault("rule:" + rule_id, set()).add(agent)
        for item in row["task"]["assigned_paths"]:
            owners.setdefault("sample:" + item["path"], set()).add(agent)
    jobs = {}
    for category, entries in (("rule", work.get("rule_tasks", [])),
                              ("sample", work.get("sample_tasks", []))):
        for row in entries:
            if category == "rule":
                key = "rule:" + row["rule_id"]
                sanitized = {k: row[k] for k in
                             ("rule_id", "evidence_anchors", "candidate_paths", "needs_new_anchor")
                             if k in row}
            else:
                key = "sample:" + row["path"]
                sanitized = {k: row[k] for k in ("path", "risk_signals") if k in row}
            targets = _source_targets(sanitized, snap["source_hashes"])
            public, expected = challenges_for(root, targets)
            task_id = digest([ledger_fingerprint(snap), digest(baseline), key])[:20]
            jobs[task_id] = {
                "task": {"schema_version": VERSION, "task_id": task_id,
                         "snapshot_fingerprint": ledger_fingerprint(snap),
                         "kind": category, "factual_anchors": sanitized,
                         "source_paths": targets, "challenge_lines": public,
                         "instruction": "只可提出反例與可重讀事實，絕不可接受第一輪 verdict"},
                "excluded_agent_ids": sorted(owners.get(key, set())),
                "estimated_tokens": max(512, sum((root / target).stat().st_size for target in targets) // 3),
                "status": "pending", "agent_instance_id": None, "claimed_at": None,
                "digest": None, "attempts": 0}
    if not jobs:
        raise ValueError("第二輪沒有本批可分派工作")
    candidate = {"version": VERSION, "snapshot_fingerprint": ledger_fingerprint(snap),
                 "baseline_digest": digest(baseline), "probe_digest": digest(probe),
                 "git_state": git_state(root),
                 "report_guard": protected_report_digest(root),
                 "workers": first["workers"], "tasks": jobs,
                 "budget_tokens": first["config"]["budget_tokens"],
                 "window_charged": first.get("window_charged", 0),
                 "measured_tokens": 0}
    destination = root / SECOND
    if destination.exists():
        old = load_json_object(destination)
        if (old.get("snapshot_fingerprint") != candidate["snapshot_fingerprint"]
                or old.get("baseline_digest") != candidate["baseline_digest"]
                or old.get("probe_digest") != candidate["probe_digest"]):
            raise ValueError("第二輪 Ledger 基準改變，不得覆寫")
        if set(old.get("tasks", {})) == set(candidate["tasks"]):
            return old
        if not advance or any(x["status"] != "accepted" for x in old["tasks"].values()):
            raise ValueError("第二輪批次已變更，須先完成舊批結果並明確 --advance")
        from multi_agent_contract import digest as object_digest
        from datetime import datetime, timezone
        archive = destination.parent / "history" / ("second-pass-" + object_digest(old)[:24] + ".json")
        archive.parent.mkdir(parents=True, exist_ok=True)
        if archive.exists():
            raise ValueError("第二輪歷史記錄已存在，拒絕覆寫")
        import os
        os.replace(destination, archive)
    write_ledger_json(destination, candidate)
    return candidate


def _active(root: Path) -> tuple[dict, dict]:
    state = load_json_object(root / SECOND)
    snap, _, _ = source_snapshot(root)
    probe = load_json_object(root / PROBE)
    first = load_json_object(root / LEDGER)
    observed = protected_report_digest(root)
    recorded = state["report_guard"]
    # The second-pass batch may span several legitimate main-agent transactions.
    # Only accept a complete contiguous chain from its initial digest.
    cursor = recorded
    for change in first.get("integration_history", []):
        if isinstance(change, dict) and change.get("before") == cursor:
            cursor = change.get("after")
    authorized_update = (recorded != observed
                         and first.get("integration") is None
                         and first.get("report_guard") == observed
                         and cursor == observed)
    if authorized_update:
        from evidence_integrity import errors as integrity_errors
        authorized_update = not integrity_errors(root)
    if (state["snapshot_fingerprint"] != ledger_fingerprint(snap)
            or state["probe_digest"] != digest(probe)
            or probe_errors(root, probe)
            or state["git_state"] != git_state(root)
            or first.get("integration") is not None
            or (recorded != observed and not authorized_update)):
        raise ValueError("第二輪 probe／來源／正式工件已異動，停止沿用回報")
    for task_id, item in state["tasks"].items():
        if item.get("digest"):
            result_file = root / ANALYSIS / "multi-agent/second-pass-results" / (task_id + ".json")
            if not result_file.is_file() or result_file.is_symlink() or digest(load_json_object(result_file)) != item["digest"]:
                raise ValueError("第二輪候選結果檔遭更動或遺失")
    return state, snap


@exclusive_ledger
def claim(root: Path, task_id: str, agent_id: str) -> dict:
    state, _ = _active(root)
    task = state["tasks"].get(task_id)
    if task is None or task["status"] not in ("pending", "failed") or task["attempts"] >= 2:
        raise ValueError("第二輪任務不可再派或已達重試上限")
    if not isinstance(agent_id, str) or not AGENT.fullmatch(agent_id):
        raise ValueError("必須提供可追溯的 executor instance ID")
    if agent_id in task["excluded_agent_ids"]:
        raise ValueError("同一子代理曾參與第一輪相同規則或樣本，禁止當作獨立複核")
    active = [x for x in state["tasks"].values() if x["status"] == "running"]
    if len(active) >= state["workers"]:
        raise ValueError("超過第二輪併發上限")
    reserved = sum(x["estimated_tokens"] for x in active)
    if state["window_charged"] + reserved + task["estimated_tokens"] > int(state["budget_tokens"] * 0.8):
        raise ValueError("第二輪預估 Token 達本批 80% 上限，停止派工")
    if any(x["agent_instance_id"] == agent_id and x["status"] == "running"
           for x in state["tasks"].values()):
        raise ValueError("相同子代理不可同時執行兩項工作")
    task["attempts"] += 1
    task["agent_instance_id"] = agent_id
    task["claimed_at"] = time.time()
    task["status"] = "running"
    write_ledger_json(root / SECOND, state)
    return {**task["task"], "agent_instance_id": agent_id}


@exclusive_ledger
def fail(root: Path, task_id: str) -> dict:
    state, _ = _active(root)
    task = state["tasks"].get(task_id)
    if task is None or task["status"] != "running":
        raise ValueError("只有 running 的第二輪任務能被標為失敗")
    task["status"] = "failed" if task["attempts"] < 2 else "needs_main"
    write_ledger_json(root / SECOND, state)
    return {"task_id": task_id, "status": task["status"],
            "fallback_required": task["status"] == "needs_main"}


@exclusive_ledger
def accept(root: Path, path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("第二輪結果檔案不存在或不安全")
    return _accept_payload(root, path.read_text("utf-8"))


@exclusive_ledger
def accept_stdin(root: Path, raw: str) -> dict:
    if len(raw.encode("utf-8")) > MAX_BYTES:
        raise ValueError("第二輪結果過大，尚未落地即拒絕")
    return _accept_payload(root, raw)


def _accept_payload(root: Path, raw: str) -> dict:
    state, snap = _active(root)
    if SECRET.search(raw):
        raise ValueError("第二輪回報疑似洩漏憑證")
    data = json.loads(raw)
    if not isinstance(data, dict) or set(data) != {
            "schema_version", "task_id", "agent_instance_id", "snapshot_fingerprint",
            "hypothesis", "line_challenges", "issues"}:
        raise ValueError("第二輪結果不符合封閉 Schema")
    row = state["tasks"].get(data["task_id"])
    if row is None:
        raise ValueError("第二輪 task_id 無效")
    payload_hash = digest(data)
    if row["status"] == "accepted":
        if row["digest"] == payload_hash:
            return {"accepted": True, "idempotent": True}
        raise ValueError("第二輪已回報內容與原始結果衝突")
    if (row["status"] != "running" or data["schema_version"] != VERSION
            or data["agent_instance_id"] != row["agent_instance_id"]
            or data["snapshot_fingerprint"] != state["snapshot_fingerprint"]):
        raise ValueError("第二輪資料與 claim 或快照不符")
    challenge = data["line_challenges"]
    expected = {file_path: {str(n): proof_line_hash(root, file_path, n) for n in lines}
                for file_path, lines in row["task"]["challenge_lines"].items()}
    if (not isinstance(challenge, dict)
            or set(challenge) != set(expected)
            or any(not isinstance(lines, list) or
                   {str(x["line"]): x["sha256"] for x in lines} != expected[path]
                   or len(lines) != len(expected[path])
                   for path, lines in challenge.items())):
        raise ValueError("第二輪隨機來源行 SHA256 挑戰不符")
    hyp = data["hypothesis"]
    if not isinstance(hyp, dict) or set(hyp) != {
            "attacker_precondition", "expected_violation", "inspection_steps",
            "observed_behavior", "evidence"}:
        raise ValueError("第二輪反例欄位不完整")
    for name in ("attacker_precondition", "expected_violation",
                 "inspection_steps", "observed_behavior"):
        if not isinstance(hyp[name], str) or not 20 <= len(hyp[name].strip()) <= 1800:
            raise ValueError("第二輪反例缺少實際調查內容")
    evidence = hyp["evidence"]
    if not isinstance(evidence, dict) or set(evidence) != {
            "path", "line_start", "line_end", "line_hash", "summary"}:
        raise ValueError("第二輪反例證據不完整")
    source = evidence["path"]
    from source_reader import read_source_text
    source_line_count = len(read_source_text(root / source)[0].splitlines()) if (
        isinstance(source, str) and source in snap["source_hashes"]) else 0
    if (not isinstance(source, str) or source not in snap["source_hashes"]
            or type(evidence["line_start"]) is not int
            or type(evidence["line_end"]) is not int
            or evidence["line_start"] <= 0
            or evidence["line_end"] < evidence["line_start"]
            or evidence["line_end"] > source_line_count
            or evidence["line_hash"] != proof_line_hash(root, source, evidence["line_start"])
            or not isinstance(evidence["summary"], str)
            or len(evidence["summary"].strip()) < 20):
        raise ValueError("第二輪反例來源行與 SHA256 不一致")
    if not isinstance(data["issues"], list) or any(
            not isinstance(x, str) or not 5 <= len(x) <= 1000 for x in data["issues"]):
        raise ValueError("第二輪未結事項無效")
    if data["issues"]:
        raise ValueError("第二輪存在未結事項，不能標記已接受；交由主代理進一步核對")
    row["status"] = "accepted"
    row["digest"] = payload_hash
    # The result is not a verdict; keep the checked artifact for main-agent adjudication.
    result_file = root / ANALYSIS / "multi-agent/second-pass-results" / (data["task_id"] + ".json")
    if result_file.exists():
        raise ValueError("第二輪交接檔已存在，不得覆寫")
    write_ledger_json(result_file, data)
    row["result_path"] = str(result_file.relative_to(root))
    state["measured_tokens"] += max(row["estimated_tokens"], 512)
    state["window_charged"] += max(row["estimated_tokens"], 512)
    write_ledger_json(root / SECOND, state)
    return {"accepted": True, "task_id": data["task_id"],
            "official_adversarial_review_completed": False,
            "notice": "只接受了可定位的挑戰候選；仍須主代理反向閱讀、裁決並透過原有 Stage/Integrate 保存"}


@exclusive_ledger
def renew_budget(root: Path) -> dict:
    state, _ = _active(root)
    if any(x["status"] == "running" for x in state["tasks"].values()):
        raise ValueError("第二輪尚有 running 工作，不得重置預算窗口")
    cap = int(state["budget_tokens"] * 0.8)
    due = [row["estimated_tokens"] for row in state["tasks"].values()
           if row["status"] in ("pending", "failed") and row["attempts"] < 2]
    if state["window_charged"] < cap and (
            not due or any(cost <= cap - state["window_charged"] for cost in due)):
        raise ValueError("第二輪仍有可派分片，無須續開窗口")
    if due and min(due) > cap:
        raise ValueError("第二輪單一任務超出上限，須主代理重切分片")
    state["window_charged"] = 0
    state["budget_window"] = state.get("budget_window", 1) + 1
    write_ledger_json(root / SECOND, state)
    return {"budget_window": state["budget_window"], "measured_tokens": state["measured_tokens"]}


def status(root: Path) -> dict:
    state, _ = _active(root)
    return {"tasks": {k: {"status": v["status"], "agent_id": v["agent_instance_id"],
                          "claimed_at": v["claimed_at"]} for k, v in state["tasks"].items()},
            "all_challenges_received": all(x["status"] == "accepted" for x in state["tasks"].values()),
            "official_second_pass_completed": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=Path.cwd())
    cmd = parser.add_mutually_exclusive_group(required=True)
    for name in ("plan", "next", "claim", "fail", "accept", "accept-stdin", "renew-budget", "status"):
        cmd.add_argument("--" + name, action="store_true")
    parser.add_argument("--advance", action="store_true")
    parser.add_argument("--task-id")
    parser.add_argument("--agent-id")
    parser.add_argument("--result", type=Path)
    args = parser.parse_args()
    try:
        root = args.target.resolve()
        if args.plan:
            state = plan(root, advance=args.advance)
            output = {"task_count": len(state["tasks"]),
                      "official_second_pass_completed": False}
        elif args.next:
            state, _ = _active(root)
            output = {"tasks": [x["task"] for x in state["tasks"].values()
                                if x["status"] in ("pending", "failed") and x["attempts"] < 2],
                      "running": {key: {"agent_id": x["agent_instance_id"],
                                       "claimed_at": x["claimed_at"]}
                                  for key, x in state["tasks"].items() if x["status"] == "running"}}
        elif args.claim:
            output = claim(root, args.task_id, args.agent_id)
        elif args.fail:
            if not args.task_id:
                raise ValueError("--fail 須指定 --task-id")
            output = fail(root, args.task_id)
        elif args.accept_stdin:
            output = accept_stdin(root, sys.stdin.read(MAX_BYTES + 1))
        elif args.renew_budget:
            output = renew_budget(root)
        elif args.accept:
            if args.result is None:
                raise ValueError("必須指定 --result")
            output = accept(root, args.result)
        else:
            output = status(root)
        print(json.dumps(output, ensure_ascii=False, separators=(",", ":")))
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print("ERROR: 第二輪分工拒絕操作：" + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
