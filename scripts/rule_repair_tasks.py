"""Deterministic, read-only rule-scoped repair tasks from authoritative blockers.

Never creates evidence, verdicts, Findings, or report mutations. Classification
priorities are repair work labels and do not change verifier diagnostics.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any
import re

RULE_ID = re.compile(r"^(?:AC|AU|IN|CR|EH|LG|DP|PD|BC|SI)-\d{2}$")
WORK_ORDER = ("P0", "P1", "P2", "P3", "P4", "P5", "unclassified")
ARTIFACTS = {
    "P0": "assessment.json",
    "P1": "analysis/rule-closures.json",
    "P2": "analysis/rule-closures.json",
    "P3": "analysis/control-verifications.json",
    "P4": "analysis/decision-audits.json",
    "P5": "assessment.json",
    "unclassified": None,
}


def classify_repair_work(message: str) -> str:
    """First matching *specific* contract wins; no speculative fallback."""
    if "缺少具體可追溯的檢核證據" in message:
        return "P0"
    if ("Q2 控制鏈" in message or "Q2 跨檔控制鏈" in message
            or "跨檔／組態候選未查證" in message):
        return "P1"
    if "規則整合／控制責任結案紀錄" in message:
        return "P2"
    if (("Q3 缺少與" in message and "控制有效性／繞過路徑證據" in message)
            or "P2 缺少控制存在、有效性與繞過路徑的查核紀錄" in message):
        return "P3"
    if ("P3 必須核對儲存庫來源與實際控制責任" in message
            or "P3 靜態結論缺少真實控制來源證據" in message):
        return "P4"
    if "缺少具體檢核摘要（至少 15 字）" in message:
        return "P5"
    return "unclassified"


def _owners(blocker: dict[str, Any]) -> tuple[str, ...]:
    raw = blocker.get("rule_ids") or []
    if not isinstance(raw, list):
        return ()
    return tuple(sorted({r for r in raw if isinstance(r, str) and RULE_ID.fullmatch(r)}))


def build_rule_repair_tasks(diagnostics: dict[str, Any], *,
                            rule_batch_size: int = 8) -> dict[str, Any]:
    """Cover every blocker index exactly once, with dependency-safe tasks.

    Task status is a read-only *work suggestion*; only fresh authoritative
    diagnosis and staged evidence can verify a repair.
    """
    if not 1 <= rule_batch_size <= 8:
        raise ValueError("rule_batch_size 必須介於 1 至 8")
    blockers = diagnostics.get("blockers", [])
    if not isinstance(blockers, list):
        raise ValueError("blockers 必須是陣列")
    grouped: dict[tuple[str, tuple[str, ...]], list[int]] = defaultdict(list)
    categories: Counter[str] = Counter()
    owners_union: set[str] = set()
    for index, blocker in enumerate(blockers):
        if not isinstance(blocker, dict):
            raise ValueError(f"blockers[{index}] 必須是物件")
        message = blocker.get("message")
        if not isinstance(message, str):
            raise ValueError(f"blockers[{index}].message 必須是字串")
        work = classify_repair_work(message)
        owners = _owners(blocker)
        # Invalid or unknown owner must never be silently assigned to a rule.
        if not owners or (blocker.get("rule_ids") or []) != list(owners):
            work = "unclassified"
        grouped[(work, owners)].append(index)
        categories[work] += 1
        owners_union.update(owners)

    ids = {(work, owners): (
        owners[0] if len(owners) == 1 else "multi:" + ",".join(owners) if owners else "unscoped"
    ) + ":" + work for work, owners in grouped}
    task_ids = set(ids.values())
    tasks = []
    for (work, owners), indexes in sorted(grouped.items(), key=lambda x: (
        WORK_ORDER.index(x[0][0]), x[0][1], x[1][0]
    )):
        deps = []
        if len(owners) == 1:
            rid = owners[0]
            required = {"P2": ("P0", "P1"), "P3": ("P0", "P1"),
                        "P4": ("P0",)}.get(work, ())
            deps = [f"{rid}:{p}" for p in required if f"{rid}:{p}" in task_ids]
        tasks.append({
            "task_id": ids[(work, owners)],
            "rule_id": owners[0] if len(owners) == 1 else None,
            "rule_ids": list(owners),
            "blocker_indexes": indexes,
            "artifact": ARTIFACTS[work],
            "priority": work,
            "depends_on": deps,
            "status": "pending",
            "requires_source_verification": True,
        })

    matrix = []
    for rid in sorted(owners_union):
        related = [t for t in tasks if rid in t["rule_ids"]]
        matrix.append({
            "rule_id": rid,
            "work_items": [w for w in WORK_ORDER if any(t["priority"] == w for t in related)],
            "blocker_count": sum(len(t["blocker_indexes"]) for t in related),
        })

    # Coalesce every P2/P3 task for a rule into the same batch, including
    # P0/P1/P4/P5 tasks for that rule. Single-writer integration is separate.
    batches = []
    rules = sorted(owners_union, key=lambda rid: (
        min((WORK_ORDER.index(t["priority"]) for t in tasks
             if t["rule_id"] == rid), default=len(WORK_ORDER)), rid
    ))
    for offset in range(0, len(rules), rule_batch_size):
        members = rules[offset:offset + rule_batch_size]
        batches.append({
            "batch_id": f"rules-{len(batches) + 1:02d}",
            "rule_ids": members,
            "task_ids": [t["task_id"] for rid in members for t in tasks
                         if t["rule_id"] == rid],
            "status": "pending",
        })

    assigned = [i for t in tasks for i in t["blocker_indexes"]]
    expected = set(range(len(blockers)))
    observed = set(assigned)
    duplicates = sorted(i for i, count in Counter(assigned).items() if count != 1)
    unknown = sorted(i for t in tasks if t["priority"] == "unclassified"
                     for i in t["blocker_indexes"])
    count_matches = diagnostics.get("blocked_count", len(blockers)) == len(blockers)
    return {
        "schema_version": 1,
        "blocker_signature": diagnostics.get("blocker_signature"),
        "work_counts": {p: categories[p] for p in WORK_ORDER},
        "rule_repair_tasks": tasks,
        "rule_work_matrix": matrix,
        "rule_repair_batches": batches,
        "rule_batch_size": rule_batch_size,
        "unscoped_task_ids": [t["task_id"] for t in tasks if t["rule_id"] is None],
        "task_coverage": {
            "blocker_total": len(blockers),
            "assigned_count": len(assigned),
            "missing_indexes": sorted(expected - observed),
            "duplicate_indexes": duplicates,
            "unclassified_indexes": unknown,
            "count_matches_diagnostic": count_matches,
            "affected_rule_count": len(owners_union),
            "task_count": len(tasks),
            "valid": not (expected - observed or duplicates or unknown or not count_matches),
        },
        "read_only": True,
        "note": "任務僅依權威 blocker 分類，不代表來源已查核、控制有效或准許整合；未知錯誤不可放行。",
    }
