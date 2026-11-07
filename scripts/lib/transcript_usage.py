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
from pathlib import Path
from typing import Iterable

SKILL_MARKER = "security-code-review"
SKILL_SCRIPTS = frozenset(
    p.stem for p in (Path(__file__).resolve().parents[1]).glob("*.py"))
_SCRIPT_RE = re.compile(r"([a-z_0-9]+)\.py\b")
_CODEGRAPH_CLI_RE = re.compile(
    r"(^|[\s;&|\"'/\\])codegraph(\.exe)?\s+(explore|query|search|context|callers|callees|files|status)",
    re.I)
_SOURCE_READ_RE = re.compile(r"(^|[\s;&|(])(cat|head|tail|sed|grep|rg|find|wc|awk|Get-Content|Select-String)\b")
_CODEGRAPH_AVAILABLE_RE = re.compile(r'\\*"codegraph\\*"\s*:\s*\{[^{}]{0,80}?\\*"available\\*"\s*:\s*true')
_READ_TOOLS = frozenset({"Read", "Grep", "Glob", "NotebookRead"})
_WRITE_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit"})
_AGENT_TOOLS = frozenset({"Agent", "Task"})
_USAGE_KEYS = ("input_tokens", "cache_read_input_tokens", "cache_creation_input_tokens", "output_tokens")


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


def summarize_transcript(path: Path) -> dict:
    """統計單一 JSONL 對話紀錄；回傳不含任何對話內容，只含數字與階段名稱。"""
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
            call = calls[key] = {"usage": usage, "phases": [], "codegraph": 0}
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
    return {
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


def summarize_session(transcript: Path) -> dict:
    """主對話加上同名目錄下 subagents/*.jsonl 的子代理紀錄。"""
    summary = summarize_transcript(transcript)
    sub_dir = transcript.with_suffix("") / "subagents"
    subagents = [summarize_transcript(p) for p in sorted(sub_dir.glob("*.jsonl"))] if sub_dir.is_dir() else []
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


def summarize_directory(directory: Path, *, session: str | None = None,
                        include_all: bool = False) -> list[dict]:
    results = []
    for transcript in sorted(directory.glob("*.jsonl")):
        if session and not transcript.stem.startswith(session):
            continue
        summary = summarize_session(transcript)
        if include_all or session or summary["skill_invoked"]:
            results.append(summary)
    return results


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
    args = parser.parse_args(argv)
    if (args.target is None) == (args.transcripts is None):
        parser.error("須擇一提供 --target 或 --transcripts")
    directory = args.transcripts or (args.projects_root or default_projects_root()) / project_dir_name(args.target)
    if not directory.is_dir():
        parser.error(f"找不到對話紀錄目錄：{directory}")
    results = summarize_directory(directory, session=args.session, include_all=args.all)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print(json.dumps(results, ensure_ascii=False, indent=2) if args.json else _format_table(results))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
