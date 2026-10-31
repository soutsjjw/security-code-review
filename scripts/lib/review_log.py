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
from review_core import REPORT_ROOT, write_json_atomic as _atomic

REPORT = REPORT_ROOT
PHASES = ("initialization", "structure_index", "queue", "first_pass",
          "cross_file_analysis", "second_pass", "validation", "report")
COUNTERS = ("completed_rules", "reviewed_files", "verified_callsites",
            "second_pass_rules", "remaining_rules", "input_tokens", "output_tokens",
            "recorded_file_reviews", "verified_file_reviews", "invalid_file_reviews",
            "integrated_transactions")
# 正式整合交易序號只在 Stage／Integrate 成功提交時遞增：第二輪與已完成證據修訂期間
# 規則數與檔案數不再增加，仍屬實際進展；失敗重試不會遞增，停滯偵測照常生效。
PROGRESS = ("completed_rules", "reviewed_files", "verified_callsites",
            "second_pass_rules", "integrated_transactions")
STALL_CHECKPOINTS = 4
STALL_SECONDS = 900
# 兩次 Log 呼叫之間超過此秒數即記為閒置空檔；只供觀測，不觸發停滯或改變守門。
IDLE_GAP_SECONDS = 900
# 只有 CLI 會自動回報的計數器才預設為 0；其餘未回報前保持缺席，避免 0 被誤讀為實測值。
AUTO_PROGRESS = ("completed_rules", "reviewed_files", "integrated_transactions")
RUN_ID = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{8}$")


def _clock() -> float:
    return time.time()


def _iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def load_metadata(path: Path) -> dict | None:
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


def log_paths(target: Path) -> tuple[Path, Path]:
    folder = target.resolve() / REPORT / "logs"
    if folder.parent.is_symlink() or folder.is_symlink():
        raise ValueError("報告或 Log 目錄不可為 symbolic link")
    return folder, folder / "latest.json"


def append_event(folder: Path, state: dict, event: str, phase: str,
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


def save_metadata(folder: Path, state: dict) -> None:
    _atomic(folder / (state["run_id"] + "-summary.json"), state)
    _atomic(folder / "latest.json", state)


def start(target: Path, *, new_review: bool = False) -> dict:
    folder, latest = log_paths(target)
    folder.mkdir(parents=True, exist_ok=True)
    previous = load_metadata(latest)
    if previous and previous.get("status") in ("running", "stalled"):
        previous["status"] = "interrupted"
        previous["finished_at"] = _iso()
        append_event(folder, previous, "run_finished", previous.get("phase", "initialization"),
                outcome="interrupted")
        _atomic(folder / (previous["run_id"] + "-summary.json"), previous)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
    same_review = bool(previous) and not new_review
    state = {
        "review_id": previous.get("review_id") if same_review else uuid.uuid4().hex,
        "run_id": run_id, "status": "running", "phase": "initialization",
        "started_at": _iso(), "started_epoch": _clock(), "finished_at": None,
        "last_progress_epoch": _clock(), "no_progress_checkpoints": 0,
        "progress": {name: 0 for name in AUTO_PROGRESS},
        "commands": 0, "command_seconds": {}, "phase_wall_seconds": {},
        "last_event_epoch": _clock(), "checkpoints": 0,
        "token_usage": {},
        "note": "執行 Log 非審查證據；必須通過既有來源與安全完整性守門",
    }
    if same_review:
        # latest.json 只指向最新 run；保留前一 run 的指標，避免短暫續跑遮蔽真正的審查回合。
        state["previous_run"] = {key: previous.get(key) for key in
                                 ("run_id", "status", "started_at", "finished_at",
                                  "elapsed_seconds")}
        if previous.get("second_pass_started"):
            state["second_pass_started"] = True
    append_event(folder, state, "run_started", "initialization")
    save_metadata(folder, state)
    return state


def _active(target: Path, *, attach: bool = False) -> tuple[Path, dict]:
    """attach=True 時，唯讀查詢與事後註記沿用已完成的 run，不另開新 run 覆寫 latest.json。"""
    folder, latest = log_paths(target)
    state = load_metadata(latest)
    if state is not None and attach and state.get("status") == "completed":
        return folder, state
    if state is None or state.get("status") in ("completed", "failed", "interrupted"):
        state = start(target)
    return folder, state


def _advance_phase(folder: Path, state: dict, phase: str) -> None:
    now = _clock()
    previous = state.get("phase", "initialization")
    seconds = max(0.0, now - state.get("last_event_epoch", now))
    wall = state.setdefault("phase_wall_seconds", {})
    wall[previous] = round(wall.get(previous, 0.0) + seconds, 3)
    if seconds >= IDLE_GAP_SECONDS:
        # 無背景心跳：Agent 長時間沒有呼叫任何 CLI 時，只能在下一次呼叫時補記這段空檔。
        idle = state.setdefault("idle_observation",
                                {"count": 0, "total_seconds": 0.0, "longest_seconds": 0.0})
        idle["count"] += 1
        idle["total_seconds"] = round(idle["total_seconds"] + seconds, 3)
        idle["longest_seconds"] = round(max(idle["longest_seconds"], seconds), 3)
        append_event(folder, state, "idle_gap", previous, outcome="review",
                metrics={"seconds": round(seconds, 3), "next_phase": phase})
    state["last_event_epoch"] = now
    state["phase"] = phase


def command(target: Path, phase: str, operation: str, seconds: float, exit_code: int,
            *, readonly: bool = False) -> str:
    """記錄一次 CLI 耗時與退出碼，回傳實際歸類的階段。"""
    if phase not in PHASES:
        raise ValueError("未知 Log 階段")
    folder, state = _active(target, attach=readonly)
    if phase == "first_pass" and state.get("second_pass_started"):
        # 第二輪沿用 review_safety --stage／--integrate，依本次審查是否已開始第二輪歸類。
        phase = "second_pass"
    if state["status"] != "completed":
        _advance_phase(folder, state, phase)
    if operation in ("begin-second-pass", "restart-second-pass") and exit_code == 0:
        state["second_pass_started"] = True
    state["commands"] += 1
    durations = state["command_seconds"]
    durations[operation] = round(durations.get(operation, 0.0) + max(0.0, seconds), 3)
    append_event(folder, state, operation, phase, elapsed_seconds=seconds,
            outcome="ok" if exit_code == 0 else "error",
            metrics={"exit_code": exit_code})
    save_metadata(folder, state)
    return phase


def checkpoint(target: Path, phase: str, metrics: dict[str, int]) -> dict:
    if phase not in PHASES:
        raise ValueError("未知 Log 階段")
    if not metrics or any(key not in COUNTERS or type(value) is not int or value < 0
                          for key, value in metrics.items()):
        raise ValueError("Log 只允許已觀測的非負整數進度／Token 數值")
    folder, state = _active(target, attach=True)
    if state["status"] == "stalled":
        # 必須另開一個 run 才能重試，防止永遠繞過停滯。
        return state
    if state["status"] == "completed" and any(
            metrics[k] < state["progress"].get(k, 0) for k in PROGRESS if k in metrics):
        # 計數倒退代表已開始新的審查工作（例如重新 --init），不可改寫已完成 run 的摘要。
        state = start(target)
    if state["status"] == "completed":
        # 完成後補記的最終進度寫回同一 run，不再計時、不參與停滯判定。
        _record_counters(state, metrics)
        append_event(folder, state, "checkpoint", phase, outcome="completed", metrics=metrics)
        save_metadata(folder, state)
        return state
    _advance_phase(folder, state, phase)
    state["checkpoints"] += 1
    # 舊版 run 或未回報過的計數器以 0 比較，但不寫入未觀測的欄位。
    before = state["progress"]
    regressions = {key: {"before": before.get(key, 0), "after": metrics[key]}
                   for key in PROGRESS if key in metrics and metrics[key] < before.get(key, 0)}
    advance = any(metrics[k] > before.get(k, 0) for k in PROGRESS if k in metrics)
    if regressions:
        append_event(folder, state, "progress_regression", phase, outcome="review",
                metrics={"counters": regressions})
    if advance:
        state["last_progress_epoch"] = _clock()
        state["no_progress_checkpoints"] = 0
    else:
        state["no_progress_checkpoints"] += 1
    _record_counters(state, metrics)
    stopped_for = max(0.0, _clock() - state["last_progress_epoch"])
    stalled = (state["no_progress_checkpoints"] >= STALL_CHECKPOINTS
               and stopped_for >= STALL_SECONDS)
    # 新的 opt-in 收斂控制只標記診斷需求，不以時間／checkpoint 直接停止。
    optimized = os.environ.get("SECURITY_CODE_REVIEW_EXECUTION_MODE") == "optimized"
    if stalled and not optimized:
        state["status"] = "stalled"
    if stalled and optimized:
        state.setdefault("convergence", {})["checkpoint_diagnostic_required"] = True
    event = ("non_converging_checkpoint" if stalled and optimized else
             "stalled" if stalled else "checkpoint")
    append_event(folder, state, event, phase,
            outcome="review" if stalled and optimized else "blocked" if stalled else "running",
            metrics=metrics)
    save_metadata(folder, state)
    return state


def _record_counters(state: dict, metrics: dict[str, int]) -> None:
    progress = state["progress"]
    for key in PROGRESS:
        if key in metrics:
            progress[key] = metrics[key]
    for key in ("input_tokens", "output_tokens"):
        if key in metrics:
            # 只有 Agent/執行器明確提供時才統計；不得推估。
            state.setdefault("token_usage", {})[key] = metrics[key]
    for key in ("recorded_file_reviews", "verified_file_reviews", "invalid_file_reviews"):
        if key in metrics:
            state.setdefault("coverage_observation", {})[key] = metrics[key]


def finish(target: Path, status: str) -> dict:
    if status not in ("completed", "failed", "interrupted", "blocked"):
        raise ValueError("不支援的執行結束狀態")
    folder, state = _active(target, attach=status == "completed")
    if state["status"] == "completed":
        # 報告 CLI 已自動結束此 run；重複的 finish --status completed 不另開空 run。
        return state
    _advance_phase(folder, state, state["phase"])
    state["status"] = status
    state["finished_at"] = _iso()
    state["elapsed_seconds"] = round(max(0.0, _clock() - state["started_epoch"]), 3)
    append_event(folder, state, "run_finished", state["phase"], outcome=status,
            elapsed_seconds=state["elapsed_seconds"])
    save_metadata(folder, state)
    return state


def observe_blockers(target: Path, diagnostics: dict) -> dict:
    """P4-A：只記錄權威 blocker 指紋差異，不修改安全判定或修復次數上限。"""
    if not isinstance(diagnostics, dict) or not isinstance(diagnostics.get("blockers"), list):
        raise ValueError("blocker diagnostics 格式錯誤")
    folder, state = _active(target, attach=True)
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
    append_event(folder, state, "blocker_diagnosed", "first_pass", metrics=delta)
    save_metadata(folder, state)
    return delta


def record_profile(target: Path, phase: str, operation: str, durations: dict[str, float]) -> None:
    """僅記錄計時，不參與完成進度、檔案證據或 SHA256 完整性判定。"""
    if phase not in PHASES or not durations:
        return
    folder, state = _active(target, attach=True)
    if state["status"] == "stalled":
        return
    safe = {name: round(max(0.0, seconds), 3)
            for name, seconds in durations.items()
            if re.fullmatch(r"[a-z][a-z0-9_]{0,47}", name) and isinstance(seconds, (int, float))}
    append_event(folder, state, operation + "_profile", phase, metrics={"seconds": safe})
    save_metadata(folder, state)


def observe_coverage(target: Path, *, recorded: int, verified: int) -> None:
    """正式完整驗證之後保存可觀測覆蓋數，不推導任何安全判定。"""
    if recorded < 0 or verified < 0:
        raise ValueError("覆蓋數不能為負")
    folder, state = _active(target, attach=True)
    if state["status"] == "stalled":
        return
    previous = state.get("coverage_observation", {})
    counts = {"recorded_file_reviews": recorded, "verified_file_reviews": verified,
              "unverified_file_reviews": max(0, recorded - verified)}
    if verified < previous.get("verified_file_reviews", 0):
        append_event(folder, state, "verified_coverage_regression", "queue", outcome="review",
                metrics={"previous": previous["verified_file_reviews"], "current": verified})
    state["coverage_observation"] = counts
    append_event(folder, state, "formal_coverage_observed", "queue", metrics=counts)
    save_metadata(folder, state)


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
        prior = load_metadata(log_paths(target)[1])
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
    # 佇列查詢與重產報告不開新 run；已完成的審查回合仍是 latest.json。
    readonly = readonly_diagnostic or (operation == "query" and phase in ("queue", "report"))
    try:
        exit_code = main()
    except Exception:
        _log_best_effort(target, phase, operation, time.perf_counter() - start_at, 2,
                         readonly=readonly)
        raise
    _log_best_effort(target, phase, operation, time.perf_counter() - start_at, exit_code,
                     readonly=readonly)
    return exit_code


def _log_best_effort(target: Path, phase: str, operation: str, seconds: float, code: int,
                     *, readonly: bool = False) -> None:
    if not (target / REPORT).is_dir():
        return
    try:
        phase = command(target, phase, operation, seconds, code, readonly=readonly)
        if operation == "integrate" and code == 0:
            # 成功整合即同步交易序號，不必等下一次 --compact 查詢，第二輪摘要才不會停在舊值。
            from evidence_integrity import integrated_sequence
            sequence = integrated_sequence(target)
            if sequence is not None:
                checkpoint(target, phase, {"integrated_transactions": sequence})
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
            state = load_metadata(log_paths(args.target)[1]) or {}
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"ERROR: Log 操作失敗（{type(exc).__name__}）", file=sys.stderr)
        return 2
    print(json.dumps(state, ensure_ascii=False, indent=2))
    return 3 if state.get("status") == "stalled" else 0


if __name__ == "__main__":
    raise SystemExit(main())
