#!/usr/bin/env python3
"""從 Claude Code 對話紀錄（JSONL）統計審查的實際 Token 用量；只讀紀錄，不臆測。

Claude Code 會把同一則 assistant 訊息依內容區塊拆成多行，且每行重複帶相同 usage；
本模組以 message id 去重，取輸出 Token 最大的一筆作為該次 API 呼叫的最終用量。
階段歸屬是啟發式：依該次呼叫實際發出的工具呼叫判斷，結果只供成本比較，
不計入來源覆蓋，也不寫入任何安全結論。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from review_core import REPORT_ROOT

SKILL_MARKER = "security-code-review"
SKILL_SCRIPTS = frozenset(
    p.stem for p in (Path(__file__).resolve().parents[1]).glob("*.py"))
_SCRIPT_RE = re.compile(r"([a-z_0-9]+)\.py\b")
_CODEGRAPH_CLI_RE = re.compile(
    r"(^|[\s;&|\"'/\\])codegraph(\.exe)?\s+(explore|query|search|context|callers|callees|files|status)",
    re.I)
_SOURCE_READ_RE = re.compile(r"(^|[\s;&|(])(cat|head|tail|sed|grep|rg|find|wc|awk|Get-Content|Select-String)\b")
# 同時接受 JSON（"codegraph": {...}）與 key=value 輸出（codegraph={...}）；引號可能被跳脫。
_CODEGRAPH_AVAILABLE_RE = re.compile(
    r'(?<![\w.])\\*"?codegraph\\*"?\s*[:=]\s*\{[^{}]{0,80}?\\*"available\\*"\s*:\s*true')
_READ_TOOLS = frozenset({"Read", "Grep", "Glob", "NotebookRead"})
_WRITE_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit"})
_AGENT_TOOLS = frozenset({"Agent", "Task"})
_USAGE_KEYS = ("input_tokens", "cache_read_input_tokens", "cache_creation_input_tokens", "output_tokens")
# 審查執行 Log 的階段窗口；依時間把每次 API 呼叫歸入其一。
REVIEW_PHASES = ("before_run", "setup_and_first_pass", "second_pass", "finalize", "after_run")
_SECOND_PASS_EVENTS = frozenset({"begin-second-pass", "restart-second-pass"})
# 相鄰兩次 API 呼叫間隔超過此秒數，視為等待（例如中斷後等使用者回來），不是審查工作時間。
IDLE_GAP_SECONDS = 600


def project_dir_name(target: Path) -> str:
    """Claude Code 以絕對路徑中每個非英數字元換成 '-' 作為專案紀錄目錄名稱。"""
    return re.sub(r"[^A-Za-z0-9]", "-", str(target.resolve()))


def default_projects_root() -> Path:
    return Path.home() / ".claude" / "projects"


def _tool_text(block: dict) -> str:
    data = block.get("input")
    if isinstance(data, dict) and isinstance(data.get("command"), str):
        return data["command"]
    return json.dumps(data, ensure_ascii=False)


def classify_tool_use(block: dict) -> tuple[str, bool]:
    """回傳（階段名稱，是否為 CodeGraph 查詢）。"""
    name = block.get("name") or ""
    text = _tool_text(block)
    if "codegraph" in name.lower():
        return "codegraph", True
    if name in _AGENT_TOOLS:
        return "subagent_dispatch", False
    scripts = sorted(s for s in _SCRIPT_RE.findall(text) if s in SKILL_SCRIPTS)
    if scripts:
        return f"skill:{scripts[0]}", bool(_CODEGRAPH_CLI_RE.search(text))
    if _CODEGRAPH_CLI_RE.search(text):
        return "codegraph", True
    if name in _READ_TOOLS:
        return "source_read", False
    if name in _WRITE_TOOLS:
        return "authoring", False
    if name in ("Bash", "PowerShell"):
        if "<<" in text or "Set-Content" in text or "Out-File" in text:
            return "authoring", False
        if _SOURCE_READ_RE.search(text):
            return "source_read", False
        return "shell_other", False
    return "other", False


def _empty_bucket() -> dict:
    return {"api_calls": 0, **{k: 0 for k in _USAGE_KEYS}}


def _add(bucket: dict, usage: dict) -> None:
    bucket["api_calls"] += 1
    for key in _USAGE_KEYS:
        bucket[key] += int(usage.get(key) or 0)


def _read_lines(path: Path) -> Iterable[dict]:
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                yield row


def _parse_ts(value) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def load_run_windows(path: Path) -> dict:
    """讀取審查執行 Log（<run_id>.jsonl，或指向它的 latest.json／-summary.json），
    以 run_started、begin-second-pass、最後一次第二輪 stage／integrate、run_finished 切出階段窗口。"""
    if path.suffix.lower() == ".json":
        meta = json.loads(path.read_text(encoding="utf-8"))
        run_id = meta.get("run_id") if isinstance(meta, dict) else None
        if not isinstance(run_id, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", run_id):
            raise ValueError(f"{path} 沒有有效的 run_id")
        path = path.with_name(run_id + ".jsonl")
    events = sorted(((ts, row) for row in _read_lines(path) if (ts := _parse_ts(row.get("timestamp")))),
                    key=lambda item: item[0])
    if not events:
        raise ValueError(f"{path} 沒有帶時間戳的事件")

    def first(predicate):
        return next((ts for ts, row in events if predicate(row)), None)

    start = first(lambda r: r.get("event") == "run_started") or events[0][0]
    finished = first(lambda r: r.get("event") == "run_finished")
    end = finished or events[-1][0]
    bounds = [("setup_and_first_pass", start)]
    second = first(lambda r: r.get("event") in _SECOND_PASS_EVENTS and r.get("outcome", "ok") == "ok")
    if second:
        bounds.append(("second_pass", second))
        last_batch = max((ts for ts, r in events if r.get("phase") == "second_pass"
                          and r.get("event") in ("stage", "integrate") and ts <= end), default=second)
        bounds.append(("finalize", last_batch))
    last = events[-1][1]
    return {"run_id": last.get("run_id") or path.stem, "path": str(path),
            "started_at": start.isoformat(), "finished_at": finished.isoformat() if finished else None,
            "bounds": bounds, "end": end}


def review_phase_for(ts: datetime | None, windows: dict) -> str | None:
    if ts is None:
        return None
    if ts < windows["bounds"][0][1]:
        return "before_run"
    if ts > windows["end"]:
        return "after_run"
    name = windows["bounds"][0][0]
    for phase, boundary in windows["bounds"]:
        if ts >= boundary:
            name = phase
    return name


def _phase_bucket() -> dict:
    return {**_empty_bucket(), "max_context_tokens": 0, "wait_seconds": 0}


def summarize_transcript(path: Path, windows: dict | None = None) -> dict:
    """統計單一 JSONL 對話紀錄；回傳不含任何對話內容，只含數字與階段名稱。
    提供 windows（load_run_windows 的結果）時另依審查階段彙整用量與等待時間。"""
    calls: dict[str, dict] = {}
    order: list[str] = []
    skill_invoked = multi_agent_requested = codegraph_available = False
    for row in _read_lines(path):
        message = row.get("message") if isinstance(row.get("message"), dict) else {}
        content = message.get("content")
        if row.get("type") == "user":
            text = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)
            if SKILL_MARKER in text and ("<command-name>" in text or "Base directory for this skill" in text):
                skill_invoked = True
            if "--multi-agent" in text and "<command-args>" in text:
                multi_agent_requested = True
            if not codegraph_available and _CODEGRAPH_AVAILABLE_RE.search(text):
                codegraph_available = True
            continue
        usage = message.get("usage")
        if row.get("type") != "assistant" or not isinstance(usage, dict):
            continue
        key = message.get("id") or row.get("requestId") or row.get("uuid") or str(len(order))
        call = calls.get(key)
        if call is None:
            call = calls[key] = {"usage": usage, "phases": [], "codegraph": 0,
                                 "ts": _parse_ts(row.get("timestamp"))}
            order.append(key)
        elif int(usage.get("output_tokens") or 0) >= int(call["usage"].get("output_tokens") or 0):
            call["usage"] = usage
        for block in content if isinstance(content, list) else []:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                phase, is_codegraph = classify_tool_use(block)
                call["phases"].append(phase)
                call["codegraph"] += int(is_codegraph)
                if phase == "skill:multi_agent":
                    multi_agent_requested = True

    totals, phases = _empty_bucket(), {}
    max_context = codegraph_calls = 0
    for key in order:
        call = calls[key]
        usage = call["usage"]
        _add(totals, usage)
        context = sum(int(usage.get(k) or 0) for k in _USAGE_KEYS[:3])
        max_context = max(max_context, context)
        codegraph_calls += call["codegraph"]
        # 同一次呼叫若發出多個工具呼叫，以第一個 skill 階段為準，否則取第一個工具類別。
        named = [p for p in call["phases"] if p.startswith("skill:")] or call["phases"] or ["no_tool"]
        _add(phases.setdefault(named[0], _empty_bucket()), usage)
    contexts = totals["input_tokens"] + totals["cache_read_input_tokens"] + totals["cache_creation_input_tokens"]
    review_phases: dict[str, dict] = {}
    if windows is not None:
        previous = None
        for call in sorted((calls[k] for k in order if calls[k]["ts"]), key=lambda c: c["ts"]):
            bucket = review_phases.setdefault(review_phase_for(call["ts"], windows), _phase_bucket())
            _add(bucket, call["usage"])
            bucket["max_context_tokens"] = max(
                bucket["max_context_tokens"], sum(int(call["usage"].get(k) or 0) for k in _USAGE_KEYS[:3]))
            if previous is not None:
                gap = (call["ts"] - previous).total_seconds()
                if gap > IDLE_GAP_SECONDS:
                    bucket["wait_seconds"] += round(gap)
            previous = call["ts"]
    result = {
        "session_id": path.stem,
        "skill_invoked": skill_invoked,
        "totals": totals,
        "max_context_tokens": max_context,
        "mean_context_tokens": round(contexts / totals["api_calls"]) if totals["api_calls"] else 0,
        "phases": dict(sorted(phases.items(), key=lambda kv: -kv[1]["cache_read_input_tokens"])),
        "subagent_dispatch_calls": sum(1 for k in order for p in calls[k]["phases"] if p == "subagent_dispatch"),
        "multi_agent_requested": multi_agent_requested,
        "codegraph_available": codegraph_available,
        "codegraph_calls": codegraph_calls,
    }
    if windows is not None:
        result["review_phases"] = {p: review_phases[p] for p in REVIEW_PHASES if p in review_phases}
    return result


def summarize_session(transcript: Path, windows: dict | None = None) -> dict:
    """主對話加上同名目錄下 subagents/*.jsonl 的子代理紀錄。
    審查階段用量含子代理呼叫；等待時間只看主對話（子代理平行執行，間隔不代表等待）。"""
    summary = summarize_transcript(transcript, windows)
    sub_dir = transcript.with_suffix("") / "subagents"
    subagents = ([summarize_transcript(p, windows) for p in sorted(sub_dir.glob("*.jsonl"))]
                 if sub_dir.is_dir() else [])
    if windows is not None:
        merged = summary["review_phases"]
        for sub in subagents:
            for phase, bucket in sub["review_phases"].items():
                target = merged.setdefault(phase, _phase_bucket())
                for key in ("api_calls", *_USAGE_KEYS):
                    target[key] += bucket[key]
                target["max_context_tokens"] = max(target["max_context_tokens"], bucket["max_context_tokens"])
        summary["review_phases"] = {p: merged[p] for p in REVIEW_PHASES if p in merged}
        summary["run_log"] = {k: windows[k] for k in ("run_id", "started_at", "finished_at")}
    sub_totals = _empty_bucket()
    for sub in subagents:
        for key, value in sub["totals"].items():
            sub_totals[key] += value
    summary["subagent_transcripts"] = len(subagents)
    summary["subagent_totals"] = sub_totals
    summary["subagent_max_context_tokens"] = max((s["max_context_tokens"] for s in subagents), default=0)
    summary["codegraph_calls"] += sum(s["codegraph_calls"] for s in subagents)
    warnings = []
    if summary["multi_agent_requested"] and not subagents:
        warnings.append("multi_agent_without_subagents")
    if summary["codegraph_available"] and summary["codegraph_calls"] == 0:
        warnings.append("codegraph_available_but_unused")
    summary["warnings"] = warnings
    return summary


def _overlaps_run(summary: dict) -> bool:
    return any(p not in ("before_run", "after_run") for p in summary.get("review_phases", {}))


def summarize_directory(directory: Path, *, session: str | None = None,
                        include_all: bool = False, windows: dict | None = None) -> list[dict]:
    """提供 windows 且未指定 session 時，只保留和該次審查執行時間重疊的 session。"""
    results = []
    for transcript in sorted(directory.glob("*.jsonl")):
        if session and not transcript.stem.startswith(session):
            continue
        summary = summarize_session(transcript, windows)
        if windows is not None and not session and not _overlaps_run(summary):
            continue
        if include_all or session or summary["skill_invoked"]:
            results.append(summary)
    return results


def _duration(seconds: int) -> str:
    return f"{seconds / 3600:.1f}h" if seconds >= 3600 else f"{seconds / 60:.0f}m"


def _format_table(results: list[dict]) -> str:
    lines = []
    for item in results:
        t = item["totals"]
        lines.append(
            f"{item['session_id'][:8]} calls={t['api_calls']} cache_read={t['cache_read_input_tokens'] / 1e6:.1f}M "
            f"cache_write={t['cache_creation_input_tokens'] / 1e6:.2f}M output={t['output_tokens'] / 1e3:.0f}K "
            f"max_ctx={item['max_context_tokens'] / 1e3:.0f}K mean_ctx={item['mean_context_tokens'] / 1e3:.0f}K "
            f"subagents={item['subagent_transcripts']} codegraph_calls={item['codegraph_calls']} "
            f"warnings={','.join(item['warnings']) or '-'}")
        for phase, bucket in list(item["phases"].items())[:8]:
            lines.append(f"    {phase:<34} calls={bucket['api_calls']:>4} "
                         f"cache_read={bucket['cache_read_input_tokens'] / 1e6:6.1f}M "
                         f"output={bucket['output_tokens'] / 1e3:6.0f}K")
        if "review_phases" in item:
            lines.append(f"  review phases (run {item['run_log']['run_id']}):")
            total_read = sum(b["cache_read_input_tokens"] for b in item["review_phases"].values()) or 1
            for phase, bucket in item["review_phases"].items():
                lines.append(f"    {phase:<34} calls={bucket['api_calls']:>4} "
                             f"cache_read={bucket['cache_read_input_tokens'] / 1e6:6.1f}M "
                             f"({bucket['cache_read_input_tokens'] / total_read:4.0%}) "
                             f"output={bucket['output_tokens'] / 1e3:6.0f}K "
                             f"max_ctx={bucket['max_context_tokens'] / 1e3:4.0f}K "
                             f"wait={_duration(bucket['wait_seconds'])}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="從 Claude Code 對話紀錄統計審查的實際 Token 用量、子代理數與 CodeGraph 使用情況")
    parser.add_argument("--target", type=Path, help="受測專案根目錄；用來推得對話紀錄目錄")
    parser.add_argument("--transcripts", type=Path, help="直接指定 Claude Code 專案紀錄目錄")
    parser.add_argument("--projects-root", type=Path, default=None,
                        help="Claude Code 專案紀錄根目錄，預設 ~/.claude/projects")
    parser.add_argument("--session", help="只統計 session id 以此開頭的紀錄")
    parser.add_argument("--all", action="store_true", help="包含未呼叫本 Skill 的 session")
    parser.add_argument("--json", action="store_true", help="輸出 JSON")
    parser.add_argument("--run-log", metavar="PATH|latest",
                        help="審查執行 Log（<run_id>.jsonl、-summary.json 或 latest.json）；"
                             "依審查階段拆分用量並只列與該次執行重疊的 session。"
                             "搭配 --target 可寫 latest")
    args = parser.parse_args(argv)
    if (args.target is None) == (args.transcripts is None):
        parser.error("須擇一提供 --target 或 --transcripts")
    directory = args.transcripts or (args.projects_root or default_projects_root()) / project_dir_name(args.target)
    if not directory.is_dir():
        parser.error(f"找不到對話紀錄目錄：{directory}")
    windows = None
    if args.run_log:
        if args.run_log == "latest":
            if args.target is None:
                parser.error("--run-log latest 須搭配 --target")
            run_log = args.target / REPORT_ROOT / "logs" / "latest.json"
        else:
            run_log = Path(args.run_log)
        try:
            windows = load_run_windows(run_log)
        except (OSError, ValueError) as exc:
            parser.error(f"無法讀取審查執行 Log：{exc}")
    results = summarize_directory(directory, session=args.session, include_all=args.all, windows=windows)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print(json.dumps(results, ensure_ascii=False, indent=2) if args.json else _format_table(results))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
