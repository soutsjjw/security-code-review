#!/usr/bin/env python3
"""Compare single/multi-agent results against an independently labeled fixture.

Requires completed real review runs; synthetic numbers must not be reported as
actual model performance. This tool does not change any verdict or review file.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def compare(labels: dict, single: dict, multi: dict) -> dict:
    cases = labels.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("需要事先標記的正反案例")
    identifiers = [c.get("id") for c in cases if isinstance(c, dict)]
    if (len(identifiers) != len(cases) or any(not isinstance(x, str) or not x for x in identifiers)
            or len(set(identifiers)) != len(identifiers)):
        raise ValueError("案例 ID 無效或重複")
    for item in cases:
        if item.get("vulnerable") not in (True, False) or type(item["vulnerable"]) is not bool:
            raise ValueError("案例須獨立標註 vulnerable 布林值")
    def metrics(run: dict) -> dict:
        findings = run.get("detected")
        if not isinstance(findings, list) or any(x not in identifiers for x in findings):
            raise ValueError("detected 清單必須使用標記案例 ID")
        if len(set(findings)) != len(findings):
            raise ValueError("不得重複計數 Finding")
        if (type(run.get("tokens")) is not int or run["tokens"] < 0
                or type(run.get("elapsed_seconds")) not in (int, float)
                or run["elapsed_seconds"] <= 0):
            raise ValueError("tokens/elapsed_seconds 必須為實測數字")
        found = set(findings)
        positives = {c["id"] for c in cases if c["vulnerable"]}
        negatives = set(identifiers) - positives
        tp = len(found & positives)
        fp = len(found & negatives)
        fn = len(positives - found)
        tn = len(negatives - found)
        return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                "recall": tp / (tp + fn) if tp + fn else None,
                "false_positive_rate": fp / (fp + tn) if fp + tn else None,
                "precision": tp / (tp + fp) if tp + fp else None,
                "tokens": run["tokens"], "elapsed_seconds": run["elapsed_seconds"],
                "tokens_measured": run.get("tokens_measured") is True}
    a, b = metrics(single), metrics(multi)
    return {
        "single": a, "multi": b,
        "recall_not_worse": (a["recall"] is not None and b["recall"] is not None
                            and b["recall"] >= a["recall"]),
        "false_positive_rate_not_worse": (
            a["false_positive_rate"] is not None
            and b["false_positive_rate"] is not None
            and b["false_positive_rate"] <= a["false_positive_rate"]),
        "real_token_comparison_available": a["tokens_measured"] and b["tokens_measured"],
        "same_cases": True,
        "notice": "必須另核對來源 SHA、執行器／模型／沙箱設定、70 項與正式覆蓋率；本工具僅計算標記案例指標",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--single", type=Path, required=True)
    parser.add_argument("--multi", type=Path, required=True)
    args = parser.parse_args()
    try:
        sources = [json.loads(p.read_text(encoding="utf-8"))
                   for p in (args.labels, args.single, args.multi)]
        output = compare(*sources)
    except (OSError, TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
