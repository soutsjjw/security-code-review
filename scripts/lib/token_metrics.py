#!/usr/bin/env python3
"""記錄外部執行器提供的真實 Token 計數；不臆測 AI 使用量。"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def record_usage(path: Path, *, executor: str, run_id: str, input_tokens: int,
                 output_tokens: int, cached_input_tokens: int = 0,
                 tool_calls: int | None = None) -> dict:
    if not executor.strip() or not run_id.strip():
        raise ValueError("須提供執行介面與本次執行識別")
    values = (input_tokens, output_tokens, cached_input_tokens)
    if any(type(x) is not int or x < 0 for x in values) or cached_input_tokens > input_tokens:
        raise ValueError("Token 數必須為非負整數且 cached 不大於 input")
    if tool_calls is not None and (type(tool_calls) is not int or tool_calls < 0):
        raise ValueError("工具呼叫數不合法")
    row = {"recorded_at": datetime.now(timezone.utc).isoformat(), "executor": executor,
           "run_id": run_id, "input_tokens": input_tokens,
           "output_tokens": output_tokens, "cached_input_tokens": cached_input_tokens,
           "tool_calls": tool_calls}
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as out:
        out.write(json.dumps(row, ensure_ascii=False) + "\n")
    return row


def main() -> int:
    parser = argparse.ArgumentParser(description="記錄實際 Token 使用量，供完整／增量審查比較")
    parser.add_argument("--target", type=Path, default=Path.cwd())
    parser.add_argument("--executor", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--input-tokens", type=int, required=True)
    parser.add_argument("--output-tokens", type=int, required=True)
    parser.add_argument("--cached-input-tokens", type=int, default=0)
    parser.add_argument("--tool-calls", type=int)
    args = parser.parse_args()
    path = args.target.resolve() / "reports/security-code-review/analysis/token-usage.jsonl"
    try:
        row = record_usage(path, executor=args.executor, run_id=args.run_id,
                           input_tokens=args.input_tokens, output_tokens=args.output_tokens,
                           cached_input_tokens=args.cached_input_tokens, tool_calls=args.tool_calls)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    print(json.dumps(row, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
