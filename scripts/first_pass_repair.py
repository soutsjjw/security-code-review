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
from rule_repair_tasks import build_rule_repair_tasks, compare_rule_repair_diagnostics

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
    status_by_rule = {
        check["id"]: check.get("status")
        for check in checks
        if isinstance(check, dict) and isinstance(check.get("id"), str)
    }
    na_scope = diagnostics.get("verified_na_inspection_paths") or {}
    if not isinstance(na_scope, dict):
        na_scope = {}
    verified_na_by_path: dict[str, set[str]] = defaultdict(set)
    for rid, paths in na_scope.items():
        if status_by_rule.get(rid) == "na" and isinstance(paths, list):
            for path in paths:
                if isinstance(path, str):
                    verified_na_by_path[path].add(rid)
    for check in checks:
        if not isinstance(check, dict) or not isinstance(check.get("id"), str):
            continue
        if (check.get("execution") or {}).get("state") != "completed":
            continue
        for path in (check.get("execution") or {}).get("inspected_paths") or []:
            if isinstance(path, str):
                links[path].add(check["id"])
    existing = {row["path"]: row for row in rows
                if isinstance(row, dict) and isinstance(row.get("path"), str)}
    missing_paths = {p for p in diagnostics.get("missing_source_paths", [])
                     if isinstance(p, str) and p}
    known_paths = set(existing) | missing_paths
    reasons: dict[str, Counter[str]] = defaultdict(Counter)
    source_issues: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for blocker in diagnostics.get("blockers", []):
        if not isinstance(blocker, dict):
            continue
        message = str(blocker.get("message", ""))
        path = blocker_source_path(message, known_paths)
        if path:
            category = str(blocker.get("category", "other"))
            reasons[path][category] += 1
            if len(source_issues[path]) < 12:
                source_issues[path].append({
                    "category": category,
                    "rule_ids": sorted({
                        rid for rid in (blocker.get("rule_ids") or [])
                        if isinstance(rid, str)
                    }),
                    "message": message,
                })
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
    for path in sorted(known_paths):
        row = existing.get(path, {})
        reviews = {rr.get("rule_id") for rr in (row.get("rule_reviews") or [])
                   if isinstance(rr, dict) and isinstance(rr.get("rule_id"), str)}
        missing_file_review = path not in existing
        absent = links.get(path, set()) - reviews
        # A completed 'na' check can cite files examined to establish absence,
        # without claiming the rule is applicable to those files. Only the
        # authoritative verifier may confirm those separate inspection links.
        na_scope_ids = {rid for rid in absent if status_by_rule.get(rid) == "na"}
        verified_na = sorted(na_scope_ids & verified_na_by_path.get(path, set()))
        unverified_na = sorted(na_scope_ids - set(verified_na))
        missing = sorted(absent - na_scope_ids)
        issue_count = sum(reasons.get(path, {}).values())
        if not (path in repeated_paths or missing or unverified_na or issue_count
                or path in missing_paths):
            continue
        by_path[path] = {
            "path": path,
            "missing_file_review": missing_file_review,
            "inspected_link_count": len(links.get(path, set())),
            "recorded_rule_review_count": len(reviews),
            "missing_rule_review_ids": missing,
            "na_inspection_rule_ids": sorted(na_scope_ids),
            "verified_na_inspection_rule_ids": verified_na,
            "unverified_na_inspection_rule_ids": unverified_na,
            "repeated_rule_conclusion_template": path in repeated_paths,
            "observed_source_blockers": dict(sorted(reasons.get(path, {}).items())),
            "observed_source_issue_details": source_issues.get(path, []),
            "repair_order": (
                "P0 建立缺少的逐檔審查" if missing_file_review else
                "P0 逐檔證據重讀" if path in repeated_paths or issue_count else
                "P1 規則關聯核對"
            ),
        }
    # 不推導規則適用性；同檔有多個疑點時先處理高扇出來源。
    ranked = sorted(by_path.values(), key=lambda item: (
        -int(item["repeated_rule_conclusion_template"]),
        -sum(item["observed_source_blockers"].values()),
        -(len(item["missing_rule_review_ids"]) +
          len(item["unverified_na_inspection_rule_ids"])),
        -item["inspected_link_count"],
        -int(item["missing_file_review"]), item["path"],
    ))
    category_counts = Counter(b.get("category", "other") for b in diagnostics.get("blockers", []))
    return {
        **build_rule_repair_tasks(diagnostics),
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
        "priority_note": (
            "observed_source_issue_details 是權威診斷摘錄；"
            "missing_rule_review_ids 不包含 na 檢查範圍。"
            "na_inspection_rule_ids 不代表已放行，未驗證者仍須回到來源及正式守門核對。"
        ),
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
    parser.add_argument("--previous-diagnostics", type=Path,
                        help="上一批 --diagnose-first-pass 的 JSON，執行唯讀阻塞回歸比較")
    args = parser.parse_args()
    try:
        target = args.target.resolve()
        assessment = json.loads((target / REPORT).read_text(encoding="utf-8"))
        from review_blockers import diagnose
        diag = diagnose(target, assessment)
        result = repair_plan(assessment, diag, limit=args.limit)
        if args.previous_diagnostics is not None:
            prior = json.loads(args.previous_diagnostics.read_text(encoding="utf-8"))
            result["batch_regression"] = compare_rule_repair_diagnostics(prior, diag)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 3 if result.get("batch_regression", {}).get("should_pause") else 0


if __name__ == "__main__":
    raise SystemExit(main())
