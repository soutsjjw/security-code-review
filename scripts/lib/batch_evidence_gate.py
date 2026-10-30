#!/usr/bin/env python3
"""批次新增／修訂證據的前置品質守門（不寫任何審查檔）。"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from review_completion import _template


def _reason_clusters(rows: list[dict]) -> Counter[tuple[str, str]]:
    """Per-file normalized rule conclusions, matching the formal verifier's intent."""
    counts: Counter[tuple[str, str]] = Counter()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            continue
        keys: set[str] = set()
        for rr in row.get("rule_reviews") or []:
            if isinstance(rr, dict) and isinstance(rr.get("reason"), str):
                keys.add(_template(rr["reason"].replace(row["path"], "<PATH>")))
        for key in keys:
            counts[(row["path"], key)] += 1
    return counts


def batch_quality_errors(target: Path, before: dict[str, Any], after: dict[str, Any], *,
                         changed_paths: set[str], snapshot_paths: set[str]) -> list[str]:
    """Guard revised file evidence without blocking unchanged legacy backlog.

    An applicable rule may be pending across batches; that row is deferred to formal
    review until completed. Completed rows must pass the *existing* authoritative
    file verifier immediately. Full review still validates all 70 rules and 100%.
    """
    if not changed_paths:
        return []
    from file_review_integrity import verified_file_rule_reviews
    existing = {r["path"]: r for r in before.get("file_reviews", [])
                if isinstance(r, dict) and isinstance(r.get("path"), str)}
    candidate = {r["path"]: r for r in after.get("file_reviews", [])
                 if isinstance(r, dict) and isinstance(r.get("path"), str)}
    completed = {
        c["id"] for c in after.get("checks", [])
        if isinstance(c, dict) and isinstance(c.get("id"), str)
        and (c.get("execution") or {}).get("state") == "completed"
    }
    to_verify = {
        path for path in changed_paths
        if path in candidate and all(
            isinstance(rr, dict) and rr.get("rule_id") in completed
            for rr in (candidate[path].get("rule_reviews") or [])
        )
    }
    errors: list[str] = []
    for check in after.get("checks", []):
        if not isinstance(check, dict) or (check.get("execution") or {}).get("state") != "completed":
            continue
        rid = check.get("id")
        for path in (check.get("execution") or {}).get("inspected_paths") or []:
            if path not in changed_paths:
                continue
            recorded = {rr.get("rule_id") for rr in candidate.get(path, {}).get("rule_reviews") or []
                        if isinstance(rr, dict)}
            if rid not in recorded:
                # NA represents verified investigation scope, not applicability.
                # The full file verifier below must validate this NA link.
                if check.get("status") == "na" and path in candidate:
                    continue
                errors.append(f"{path}: {rid} 已列入 inspected_paths 但缺少 rule_reviews")
    if to_verify:
        from file_review_integrity import verified_na_inspection_links
        verified, failures = verified_file_rule_reviews(after, target, snapshot_paths)
        for failure in failures:
            if any(failure.startswith(path + ":") for path in to_verify):
                errors.append("批次逐檔證據不合格：" + failure)
        na_links = verified_na_inspection_links(after, target, snapshot_paths, verified)
        for check in after.get("checks", []):
            if not isinstance(check, dict) or check.get("status") != "na":
                continue
            if (check.get("execution") or {}).get("state") != "completed":
                continue
            rid = check.get("id")
            for path in (check.get("execution") or {}).get("inspected_paths") or []:
                if path in to_verify and rid not in na_links.get(path, set()):
                    errors.append(
                        f"{path}: {rid} 不適用檢查範圍缺少有效來源或逐檔證據；"
                        "不得直接以 inspected_paths 當作已驗證關聯"
                    )

    # A repaired row must not extend an already invalid mass-template cluster.
    # Existing clusters are not silently accepted at formal validation.
    old_counts: Counter[str] = Counter()
    new_counts: Counter[str] = Counter()
    for path, row in existing.items():
        keys = {_template(rr["reason"].replace(path, "<PATH>"))
                for rr in row.get("rule_reviews") or []
                if isinstance(rr, dict) and isinstance(rr.get("reason"), str)}
        old_counts.update(keys)
    for path, row in candidate.items():
        keys = {_template(rr["reason"].replace(path, "<PATH>"))
                for rr in row.get("rule_reviews") or []
                if isinstance(rr, dict) and isinstance(rr.get("reason"), str)}
        new_counts.update(keys)
    threshold = max(15, (len(candidate) + 7) // 8)
    for template, count in new_counts.items():
        if count >= threshold and count > old_counts.get(template, 0):
            errors.append(
                f"批次新增重複的逐檔規則結論模板：{count}/{len(candidate)} 個檔案，"
                "須逐檔重新核實實際控制，不得以流水號或路徑替換制式內容"
            )
            break
    return errors
