#!/usr/bin/env python3
"""唯讀第一輪修復順序；僅提供工作清單，絕不改寫審查結果。"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from review_completion import _template

REPORT = Path("reports/security-code-review/assessment.json")
RULE_ID = r"(?:AC|AU|IN|CR|EH|LG|DP|PD|BC|SI)-\d{2}"
# Verifier emits both "path: RULE: details" and "RULE: path:line details".
FILE_RULE = re.compile(rf"^(?P<path>[^:\n]+): (?P<rule>{RULE_ID}):")
RULE_FILE = re.compile(rf"^(?P<rule>{RULE_ID}): (?P<path>[^:\n]+):")


def blocker_source_path(message: str, known_paths: set[str]) -> str | None:
    """Assign only an explicitly named, existing reviewed source path."""
    for pattern in (FILE_RULE, RULE_FILE):
        match = pattern.match(message)
        if match and match.group("path") in known_paths:
            return match.group("path")
    return None


def repair_plan(assessment: dict[str, Any], diagnostics: dict[str, Any], *,
                limit: int = 30) -> dict[str, Any]:
    """Only prioritizes *observed* gaps. No automatic rule assignments or verdict changes."""
    if limit < 1:
        raise ValueError("limit 必須大於零")
    checks = assessment.get("checks") or []
    rows = assessment.get("file_reviews") or []
    links: dict[str, set[str]] = defaultdict(set)
    for check in checks:
        if not isinstance(check, dict) or not isinstance(check.get("id"), str):
            continue
        if (check.get("execution") or {}).get("state") != "completed":
            continue
        for path in (check.get("execution") or {}).get("inspected_paths") or []:
            if isinstance(path, str):
                links[path].add(check["id"])
    known_paths = {row["path"] for row in rows
                   if isinstance(row, dict) and isinstance(row.get("path"), str)}
    reasons: dict[str, Counter[str]] = defaultdict(Counter)
    for blocker in diagnostics.get("blockers", []):
        path = blocker_source_path(str(blocker.get("message", "")), known_paths)
        if path:
            reasons[path][blocker.get("category", "other")] += 1
    clusters: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            continue
        for rr in row.get("rule_reviews") or []:
            if isinstance(rr, dict) and isinstance(rr.get("reason"), str):
                # 同正式驗證器，路徑與流水號不得讓複製模板偽裝成不同內容。
                normalized = _template(rr["reason"].replace(row["path"], "<PATH>"))
                clusters[normalized].add(row["path"])
    threshold = max(15, (len(rows) + 7) // 8)
    repeated_paths: set[str] = set()
    for paths in clusters.values():
        if len(paths) >= threshold:
            repeated_paths.update(paths)
    by_path = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            continue
        path = row["path"]
        reviews = {rr.get("rule_id") for rr in (row.get("rule_reviews") or [])
                   if isinstance(rr, dict) and isinstance(rr.get("rule_id"), str)}
        missing = sorted(links.get(path, set()) - reviews)
        issue_count = sum(reasons.get(path, {}).values())
        if not (path in repeated_paths or missing or issue_count):
            continue
        by_path[path] = {
            "path": path,
            "inspected_link_count": len(links.get(path, set())),
            "recorded_rule_review_count": len(reviews),
            "missing_rule_review_ids": missing,
            "repeated_rule_conclusion_template": path in repeated_paths,
            "observed_source_blockers": dict(sorted(reasons.get(path, {}).items())),
            "repair_order": (
                "P0 逐檔證據重讀" if path in repeated_paths or issue_count else
                "P1 規則關聯核對"
            ),
        }
    # 不推導規則適用性；同檔有多個疑點時先處理高扇出來源。
    ranked = sorted(by_path.values(), key=lambda item: (
        -int(item["repeated_rule_conclusion_template"]),
        -sum(item["observed_source_blockers"].values()),
        -len(item["missing_rule_review_ids"]),
        -item["inspected_link_count"], item["path"],
    ))
    category_counts = Counter(b.get("category", "other") for b in diagnostics.get("blockers", []))
    return {
        "ready_for_second_pass": bool(diagnostics.get("ready_for_second_pass")),
        "blocker_signature": diagnostics.get("blocker_signature"),
        "blocked_count": diagnostics.get("blocked_count"),
        "diagnostic_categories": dict(sorted(category_counts.items())),
        "reviewed_file_records": len(rows),
        "files_without_rule_reviews": sum(not r.get("rule_reviews") for r in rows if isinstance(r, dict)),
        "repeated_template_threshold": threshold,
        "suspected_template_paths": len(repeated_paths),
        "candidate_repair_file_count": len(ranked),
        "priority_files": ranked[:limit],
        "remaining_priority_files": max(0, len(ranked) - limit),
        "p2_control_rules": sorted({
            rule for b in diagnostics.get("blockers", [])
            if b.get("category") in {"control_trace", "control_outcome",
                                     "weak_source_evidence", "missing_external_decision",
                                     "integrity"}
            for rule in b.get("rule_ids", [])
        }),
        "p3_release_condition": (
            "先依真實來源修正 P0/P1/P2，再以 --diagnose-first-pass 確認 "
            "ready_for_second_pass=true；第二輪及完整報告的正式守門不可省略"
        ),
        "read_only": True,
        "note": "診斷不是可直接套用的 payload；須逐檔核實真實來源與既有 Findings，"
                "通過 --stage / --integrate --allow-revision 合法修訂。",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="唯讀排定第一輪審查證據修復順序")
    parser.add_argument("--target", type=Path, default=Path.cwd())
    parser.add_argument("--limit", type=int, default=30)
    args = parser.parse_args()
    try:
        target = args.target.resolve()
        assessment = json.loads((target / REPORT).read_text(encoding="utf-8"))
        from review_blockers import diagnose
        diag = diagnose(target, assessment)
        result = repair_plan(assessment, diag, limit=args.limit)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
