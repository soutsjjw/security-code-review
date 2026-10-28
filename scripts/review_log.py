#!/usr/bin/env python3
"""完整 70 項審查的低成本執行日誌；Log 不屬於安全證據或完成守門。"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

REPORT = Path("reports/security-code-review")
PHASES = ("initialization", "structure_index", "queue", "first_pass",
          "cross_file_analysis", "second_pass", "validation", "report")
COUNTERS = ("completed_rules", "reviewed_files", "verified_callsites",
            "second_pass_rules", "remaining_rules", "input_tokens", "output_tokens",
            "recorded_file_reviews", "verified_file_reviews", "invalid_file_reviews")
PROGRESS = COUNTERS[:4]
STALL_CHECKPOINTS = 4
STALL_SECONDS = 900
RUN_ID = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{8}$")


def _clock() -> float:
    return time.time()


def _iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _atomic(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def _load(path: Path) -> dict | None:
    if path.is_symlink():
        raise ValueError("Log metadata 不可為 symbolic link")
    if not path.is_file():
        return None
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("Log metadata 格式錯誤")
    if "run_id" in obj and (not isinstance(obj["run_id"], str)
                             or not RUN_ID.fullmatch(obj["run_id"])):
        raise ValueError("Log run_id 格式錯誤")
    return obj


def _paths(target: Path) -> tuple[Path, Path]:
    folder = target.resolve() / REPORT / "logs"
    if folder.parent.is_symlink() or folder.is_symlink():
        raise ValueError("報告或 Log 目錄不可為 symbolic link")
    return folder, folder / "latest.json"


def _append(folder: Path, state: dict, event: str, phase: str,
            *, metrics: dict | None = None, elapsed_seconds: float | None = None,
            outcome: str | None = None) -> None:
    row = {"timestamp": _iso(), "review_id": state["review_id"],
           "run_id": state["run_id"], "event": event, "phase": phase}
    if outcome is not None:
        row["outcome"] = outcome
    if elapsed_seconds is not None:
        row["elapsed_seconds"] = round(max(0.0, elapsed_seconds), 3)
    if metrics:
        row["metrics"] = metrics
    # 單代理、單行追加；不採集原始碼、憑證、Prompt 或例外訊息。
    log_file = folder / (state["run_id"] + ".jsonl")
    if log_file.is_symlink():
        raise ValueError("Log 檔案不可為 symbolic link")
    with log_file.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


def _save(folder: Path, state: dict) -> None:
    _atomic(folder / (state["run_id"] + "-summary.json"), state)
    _atomic(folder / "latest.json", state)


def start(target: Path, *, new_review: bool = False) -> dict:
    folder, latest = _paths(target)
    folder.mkdir(parents=True, exist_ok=True)
    previous = _load(latest)
    if previous and previous.get("status") in ("running", "stalled"):
        previous["status"] = "interrupted"
        previous["finished_at"] = _iso()
        _append(folder, previous, "run_finished", previous.get("phase", "initialization"),
                outcome="interrupted")
        _atomic(folder / (previous["run_id"] + "-summary.json"), previous)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
    state = {
        "review_id": (previous.get("review_id") if previous and not new_review
                      else uuid.uuid4().hex),
        "run_id": run_id, "status": "running", "phase": "initialization",
        "started_at": _iso(), "started_epoch": _clock(), "finished_at": None,
        "last_progress_epoch": _clock(), "no_progress_checkpoints": 0,
        "progress": {name: 0 for name in PROGRESS},
        "commands": 0, "command_seconds": {}, "phase_wall_seconds": {},
        "last_event_epoch": _clock(), "checkpoints": 0,
        "token_usage": {"input_tokens": 0, "output_tokens": 0},
        "note": "執行 Log 非審查證據；必須通過既有來源與安全完整性守門",
    }
    _append(folder, state, "run_started", "initialization")
    _save(folder, state)
    return state


def _active(target: Path) -> tuple[Path, dict]:
    folder, latest = _paths(target)
    state = _load(latest)
    if state is None or state.get("status") in ("completed", "failed", "interrupted"):
        state = start(target)
    return folder, state


def _advance_phase(state: dict, phase: str) -> None:
    now = _clock()
    previous = state.get("phase", "initialization")
    seconds = max(0.0, now - state.get("last_event_epoch", now))
    wall = state.setdefault("phase_wall_seconds", {})
    wall[previous] = round(wall.get(previous, 0.0) + seconds, 3)
    state["last_event_epoch"] = now
    state["phase"] = phase


def command(target: Path, phase: str, operation: str, seconds: float, exit_code: int) -> None:
    if phase not in PHASES:
        raise ValueError("未知 Log 階段")
    folder, state = _active(target)
    _advance_phase(state, phase)
    state["commands"] += 1
    durations = state["command_seconds"]
    durations[operation] = round(durations.get(operation, 0.0) + max(0.0, seconds), 3)
    _append(folder, state, operation, phase, elapsed_seconds=seconds,
            outcome="ok" if exit_code == 0 else "error",
            metrics={"exit_code": exit_code})
    _save(folder, state)


def checkpoint(target: Path, phase: str, metrics: dict[str, int]) -> dict:
    if phase not in PHASES:
        raise ValueError("未知 Log 階段")
    if not metrics or any(key not in COUNTERS or type(value) is not int or value < 0
                          for key, value in metrics.items()):
        raise ValueError("Log 只允許已觀測的非負整數進度／Token 數值")
    folder, state = _active(target)
    if state["status"] == "stalled":
        # 必須另開一個 run 才能重試，防止永遠繞過停滯。
        return state
    _advance_phase(state, phase)
    state["checkpoints"] += 1
    before = state["progress"]
    regressions = {key: {"before": before[key], "after": metrics[key]}
                   for key in PROGRESS if key in metrics and metrics[key] < before[key]}
    advance = any(metrics.get(k, before[k]) > before[k] for k in PROGRESS)
    if regressions:
        _append(folder, state, "progress_regression", phase, outcome="review",
                metrics={"counters": regressions})
    if advance:
        state["last_progress_epoch"] = _clock()
        state["no_progress_checkpoints"] = 0
    else:
        state["no_progress_checkpoints"] += 1
    for key in PROGRESS:
        if key in metrics:
            before[key] = metrics[key]
    for key in ("input_tokens", "output_tokens"):
        if key in metrics:
            # 只有 Agent/執行器明確提供時才統計；不得推估。
            state["token_usage"][key] = metrics[key]
    for key in ("recorded_file_reviews", "verified_file_reviews", "invalid_file_reviews"):
        if key in metrics:
            state.setdefault("coverage_observation", {})[key] = metrics[key]
    stopped_for = max(0.0, _clock() - state["last_progress_epoch"])
    stalled = (state["no_progress_checkpoints"] >= STALL_CHECKPOINTS
               and stopped_for >= STALL_SECONDS)
    if stalled:
        state["status"] = "stalled"
    _append(folder, state, "stalled" if stalled else "checkpoint", phase,
            outcome="blocked" if stalled else "running", metrics=metrics)
    _save(folder, state)
    return state


def finish(target: Path, status: str) -> dict:
    if status not in ("completed", "failed", "interrupted", "blocked"):
        raise ValueError("不支援的執行結束狀態")
    folder, state = _active(target)
    _advance_phase(state, state["phase"])
    state["status"] = status
    state["finished_at"] = _iso()
    state["elapsed_seconds"] = round(max(0.0, _clock() - state["started_epoch"]), 3)
    _append(folder, state, "run_finished", state["phase"], outcome=status,
            elapsed_seconds=state["elapsed_seconds"])
    _save(folder, state)
    return state



def observe_blockers(target: Path, diagnostics: dict) -> dict:
    """P4-A：只記錄權威 blocker 指紋差異，不修改安全判定或修復次數上限。"""
    if not isinstance(diagnostics, dict) or not isinstance(diagnostics.get("blockers"), list):
        raise ValueError("blocker diagnostics 格式錯誤")
    folder, state = _active(target)
    current = sorted({
        hashlib.sha256(json.dumps(
            {"category": b.get("category"), "rule_ids": b.get("rule_ids"),
             "message": b.get("message")}, sort_keys=True, ensure_ascii=False
        ).encode("utf-8")).hexdigest()
        for b in diagnostics["blockers"] if isinstance(b, dict)
    })
    old = state.get("blocker_observation") or {}
    before, after = set(old.get("fingerprints") or []), set(current)
    delta = {"blocked_count": len(after), "new_count": len(after - before),
             "resolved_count": len(before - after),
             "signature_changed": diagnostics.get("blocker_signature") != old.get("signature")}
    state["blocker_observation"] = {"signature": diagnostics.get("blocker_signature"),
                                    "count": len(after), "fingerprints": current,
                                    "last_delta": delta}
    _append(folder, state, "blocker_diagnosed", "first_pass", metrics=delta)
    _save(folder, state)
    return delta


def record_profile(target: Path, phase: str, operation: str, durations: dict[str, float]) -> None:
    """僅記錄計時，不參與完成進度、檔案證據或 SHA256 完整性判定。"""
    if phase not in PHASES or not durations:
        return
    folder, state = _active(target)
    if state["status"] == "stalled":
        return
    safe = {name: round(max(0.0, seconds), 3)
            for name, seconds in durations.items()
            if re.fullmatch(r"[a-z][a-z0-9_]{0,47}", name) and isinstance(seconds, (int, float))}
    _append(folder, state, operation + "_profile", phase, metrics={"seconds": safe})
    _save(folder, state)


def observe_coverage(target: Path, *, recorded: int, verified: int) -> None:
    """正式完整驗證之後保存可觀測覆蓋數，不推導任何安全判定。"""
    if recorded < 0 or verified < 0:
        raise ValueError("覆蓋數不能為負")
    folder, state = _active(target)
    if state["status"] == "stalled":
        return
    previous = state.get("coverage_observation", {})
    counts = {"recorded_file_reviews": recorded, "verified_file_reviews": verified,
              "unverified_file_reviews": max(0, recorded - verified)}
    if verified < previous.get("verified_file_reviews", 0):
        _append(folder, state, "verified_coverage_regression", "queue", outcome="review",
                metrics={"previous": previous["verified_file_reviews"], "current": verified})
    state["coverage_observation"] = counts
    _append(folder, state, "formal_coverage_observed", "queue", metrics=counts)
    _save(folder, state)


def logged_main(main, phase: str) -> int:
    """為既有 CLI 包裝耗時計量；不改變原本的退出碼與安全檢核決策。"""
    args = sys.argv[1:]
    if "--categories" in args or any(x.startswith("--categories=") for x in args):
        return main()
    try:
        offset = args.index("--target")
        target = Path(args[offset + 1])
    except (ValueError, IndexError):
        selected = next((s.split("=", 1)[1] for s in args if s.startswith("--target=")), None)
        target = Path(selected) if selected else Path.cwd()
    # 停滯後只容許唯讀定位／診斷；修改與正式驗證仍須明確開啟新 run。
    readonly_diagnostic = (
        ("--diagnose-first-pass" in args or "--repair-plan" in args)
        or ("--detail-id" in args and "--init" not in args)
        or ("--plan" in args and not any(x in args for x in
            ("--stage", "--integrate", "--init", "--seal-integrity")))
    )
    try:
        prior = _load(_paths(target)[1])
        if prior and prior.get("status") == "stalled" and not readonly_diagnostic:
            print("ERROR: 審查已 stalled；可先使用唯讀診斷，查明後再執行 review_log.py start 恢復。", file=sys.stderr)
            return 3
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: 無法安全讀取審查執行狀態（{type(exc).__name__}）", file=sys.stderr)
        return 2
    if prior and prior.get("status") == "stalled" and readonly_diagnostic:
        # 不得以唯讀診斷建立新 run、遞增 checkpoint 或改寫已停滯紀錄。
        return main()
    start_at = time.perf_counter()
    operation = next((part.removeprefix("--") for part in args if part.startswith("--")
                      and part not in ("--target", "--compact", "--batch-size", "--detail-id",
                                       "--mode", "--output-dir", "--source-encodings",
                                       "--source-batch-size", "--workers", "--worker-id")), "query")
    try:
        exit_code = main()
    except Exception:
        _log_best_effort(target, phase, operation, time.perf_counter() - start_at, 2)
        raise
    _log_best_effort(target, phase, operation, time.perf_counter() - start_at, exit_code)
    return exit_code


def _log_best_effort(target: Path, phase: str, operation: str, seconds: float, code: int) -> None:
    if not (target / REPORT).is_dir():
        return
    try:
        command(target, phase, operation, seconds, code)
        if phase == "report" and code == 0:
            finish(target, "completed")
    except (OSError, ValueError, KeyError) as exc:
        print(f"WARNING: Log 無法寫入（{type(exc).__name__}）；不影響資安守門結果", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description="完整審查 Log、效能量測與停滯偵測")
    parser.add_argument("--target", type=Path, default=Path.cwd())
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("start").add_argument("--new-review", action="store_true")
    p = sub.add_parser("checkpoint")
    p.add_argument("--phase", choices=PHASES, required=True)
    for key in COUNTERS:
        p.add_argument("--" + key.replace("_", "-"), dest=key, type=int)
    p = sub.add_parser("finish")
    p.add_argument("--status", choices=("completed", "failed", "interrupted", "blocked"),
                   required=True)
    sub.add_parser("status")
    args = parser.parse_args()
    try:
        if args.action == "start":
            state = start(args.target, new_review=args.new_review)
        elif args.action == "checkpoint":
            values = {k: getattr(args, k) for k in COUNTERS if getattr(args, k) is not None}
            state = checkpoint(args.target, args.phase, values)
        elif args.action == "finish":
            state = finish(args.target, args.status)
        else:
            state = _load(_paths(args.target)[1]) or {}
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"ERROR: Log 操作失敗（{type(exc).__name__}）", file=sys.stderr)
        return 2
    print(json.dumps(state, ensure_ascii=False, indent=2))
    return 3 if state.get("status") == "stalled" else 0


if __name__ == "__main__":
    raise SystemExit(main())
