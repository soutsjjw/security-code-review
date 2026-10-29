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
PREREQUISITES = {
    "P2": ("P0", "P1"),
    "P3": ("P0", "P1"),
    "P4": ("P0",),
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
    raw = blocker.get("rule_ids")
    if not isinstance(raw, list) or not raw or not all(
        isinstance(r, str) and RULE_ID.fullmatch(r) for r in raw
    ):
        return ()
    return tuple(sorted(set(raw)))


def _dependency_errors(tasks: list[dict[str, Any]]) -> list[str]:
    """Verify dependency references and detect cycles, including shared tasks."""
    lookup = {t["task_id"]: t for t in tasks}
    errors = []
    if len(lookup) != len(tasks):
        errors.append("duplicate_task_ids")
    states: dict[str, int] = {}

    def visit(task_id: str) -> None:
        state = states.get(task_id, 0)
        if state == 1:
            errors.append(f"dependency_cycle:{task_id}")
            return
        if state == 2:
            return
        states[task_id] = 1
        for dep in lookup[task_id]["depends_on"]:
            if dep not in lookup:
                errors.append(f"missing_dependency:{task_id}:{dep}")
            else:
                visit(dep)
        states[task_id] = 2

    for key in sorted(lookup):
        visit(key)
    return sorted(set(errors))



def _execution_batches(tasks: list[dict[str, Any]], rule_batch_size: int
                       ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Topologically ordered execution batches, not merely grouped work views.

    Same-owner control-closure and effectiveness tasks form one atomic bundle.
    A cross-rule bundle may execute once, before every dependent rule batch.
    All dependencies must be completed in *earlier* batches, not just listed.
    """
    # A shared control task and a single-rule control task may concern the
    # same rule. Group all overlapping closure/effectiveness tasks into atomic
    # components so none can silently split across execution batches.
    control_tasks = [t for t in tasks if t["priority"] in {"P2", "P3"}]
    parents = {t["task_id"]: t["task_id"] for t in control_tasks}

    def root(task_id: str) -> str:
        while parents[task_id] != task_id:
            task_id = parents[task_id]
        return task_id

    owner_control: dict[str, str] = {}
    for task in control_tasks:
        task_id = task["task_id"]
        for owner in task["rule_ids"]:
            previous = owner_control.setdefault(owner, task_id)
            parents[root(task_id)] = root(previous)
    components: dict[str, list[str]] = defaultdict(list)
    for task in control_tasks:
        components[root(task["task_id"])].append(task["task_id"])
    component_keys = {task_id: tuple(sorted(group))
                      for group in components.values() for task_id in group}

    bundles: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
    for task in tasks:
        key = (("control_component", component_keys[task["task_id"]])
               if task["priority"] in {"P2", "P3"}
               else ("single_task", task["task_id"]))
        bundles[key].append(task)

    def bundle_sort_key(key: tuple) -> tuple:
        group = bundles[key]
        return (min(WORK_ORDER.index(t["priority"]) for t in group),
                tuple(sorted({r for t in group for r in t["rule_ids"]})),
                tuple(sorted(t["task_id"] for t in group)))

    remaining = set(bundles)
    scheduled_task_to_batch: dict[str, str] = {}
    batches: list[dict[str, Any]] = []
    while remaining:
        # A task is ready only when all external dependencies were completed
        # in an earlier execution batch. Never waive a missing prerequisite.
        ready = sorted((
            key for key in remaining
            if all(dep in scheduled_task_to_batch
                   for task in bundles[key] for dep in task["depends_on"])
        ), key=bundle_sort_key)
        selected: list[tuple] = []
        member_rules: set[str] = set()
        for key in ready:
            owners = {rid for t in bundles[key] for rid in t["rule_ids"]}
            if len(member_rules | owners) > rule_batch_size:
                continue
            selected.append(key)
            member_rules.update(owners)
        if not selected:
            # Cycle, missing dependency, or a bundle that cannot fit. Fail closed.
            break
        task_items = sorted((task for key in selected for task in bundles[key]),
                            key=lambda t: (WORK_ORDER.index(t["priority"]),
                                           tuple(t["rule_ids"]), t["task_id"]))
        dependencies = sorted({
            scheduled_task_to_batch[dep]
            for task in task_items for dep in task["depends_on"]
        }, key=lambda b: int(b.split("-")[-1]))
        batch_id = f"execution-{len(batches) + 1:02d}"
        batches.append({
            "batch_id": batch_id,
            "rule_ids": sorted(member_rules),
            "task_ids": [t["task_id"] for t in task_items],
            "depends_on_batch_ids": dependencies,
            "status": "pending",
            "type": ("cross_rule" if any(len(t["rule_ids"]) > 1
                                         for t in task_items) else "rules"),
        })
        for task in task_items:
            scheduled_task_to_batch[task["task_id"]] = batch_id
        remaining.difference_update(selected)

    all_task_ids = {task["task_id"] for task in tasks}
    emitted = [task_id for batch in batches for task_id in batch["task_ids"]]
    emitted_count = Counter(emitted)
    unscheduled = sorted(all_task_ids - set(emitted))
    duplicate_tasks = sorted(t for t, count in emitted_count.items() if count != 1)
    foreign_tasks = sorted(set(emitted) - all_task_ids)
    forward_edges: list[str] = []
    pair_split: list[str] = []
    batch_positions = {batch["batch_id"]: i for i, batch in enumerate(batches)}
    for task in tasks:
        batch_id = scheduled_task_to_batch.get(task["task_id"])
        if batch_id is None:
            continue
        for dependency in task["depends_on"]:
            dep_batch = scheduled_task_to_batch.get(dependency)
            if dep_batch is None or batch_positions[dep_batch] >= batch_positions[batch_id]:
                forward_edges.append(f"{dependency}->{task['task_id']}")
    by_owner_control: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for task in control_tasks:
        for owner in task["rule_ids"]:
            by_owner_control[owner].append(task)
    for owner, relevant in by_owner_control.items():
        kinds = {t["priority"] for t in relevant}
        if {"P2", "P3"} <= kinds and len({
            scheduled_task_to_batch.get(t["task_id"]) for t in relevant
        }) != 1:
            pair_split.append(owner)
    over_limit = [b["batch_id"] for b in batches if len(b["rule_ids"]) > rule_batch_size]
    return batches, {
        "scheduled_task_count": len(emitted),
        "unscheduled_task_ids": unscheduled,
        "duplicate_task_ids": duplicate_tasks,
        "foreign_task_ids": foreign_tasks,
        "forward_dependency_edges": sorted(set(forward_edges)),
        "split_control_pair_rules": sorted(pair_split),
        "over_limit_batch_ids": over_limit,
        "valid": not (unscheduled or duplicate_tasks or foreign_tasks
                      or forward_edges or pair_split or over_limit),
    }



def build_rule_repair_tasks(diagnostics: dict[str, Any], *,
                            rule_batch_size: int = 8) -> dict[str, Any]:
    """One owner per blocker index, every task scheduled or explicitly invalid."""
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
        if not owners:
            work = "unclassified"
        grouped[(work, owners)].append(index)
        categories[work] += 1
        owners_union.update(owners)

    ids = {(work, owners): (
        owners[0] if len(owners) == 1 else
        "multi:" + ",".join(owners) if owners else "unscoped"
    ) + ":" + work for work, owners in grouped}
    by_rule_work: dict[tuple[str, str], set[str]] = defaultdict(set)
    for (work, owners), task_id in ids.items():
        for rid in owners:
            by_rule_work[(rid, work)].add(task_id)
    tasks = []
    for (work, owners), indexes in sorted(grouped.items(), key=lambda x: (
        WORK_ORDER.index(x[0][0]), x[0][1], x[1][0]
    )):
        deps = sorted({
            prerequisite_task
            for rid in owners for prerequisite in PREREQUISITES.get(work, ())
            for prerequisite_task in by_rule_work.get((rid, prerequisite), ())
        })
        tasks.append({
            "task_id": ids[(work, owners)],
            "rule_id": owners[0] if len(owners) == 1 else None,
            "rule_ids": list(owners),
            "blocker_indexes": indexes,
            "blocker_details": [
                {"index": index, "message": blockers[index]["message"],
                 "category": blockers[index].get("category", "other"),
                 "rule_ids": list(blockers[index].get("rule_ids") or [])}
                for index in indexes
            ],
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

    # Rule batches contain only single-rule tasks. Cross-rule tasks appear in
    # *one* dedicated shared batch, never duplicated in each owner's batch.
    # Oversized cross-rule scope is reported as unschedulable (fail closed).
    batches = []
    rules = sorted(owners_union, key=lambda rid: (
        min((WORK_ORDER.index(t["priority"]) for t in tasks
             if rid in t["rule_ids"]), default=len(WORK_ORDER)), rid
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
    shared_batches = []
    for task in tasks:
        if len(task["rule_ids"]) <= 1 or len(task["rule_ids"]) > rule_batch_size:
            continue
        shared_batches.append({
            "batch_id": f"shared-{len(shared_batches) + 1:02d}",
            "rule_ids": list(task["rule_ids"]),
            "task_ids": [task["task_id"]],
            "status": "pending",
            "type": "cross_rule",
        })

    assigned = [i for t in tasks for i in t["blocker_indexes"]]
    expected = set(range(len(blockers)))
    duplicates = sorted(i for i, count in Counter(assigned).items() if count != 1)
    unknown = sorted(i for t in tasks if t["priority"] == "unclassified"
                     for i in t["blocker_indexes"])
    batch_task_ids = [task_id for b in batches + shared_batches for task_id in b["task_ids"]]
    batch_task_counts = Counter(batch_task_ids)
    unscheduled = sorted(t["task_id"] for t in tasks
                         if batch_task_counts[t["task_id"]] == 0)
    duplicated_batch_tasks = sorted(t for t, count in batch_task_counts.items() if count > 1)
    foreign_batch_tasks = sorted(set(batch_task_ids) - {t["task_id"] for t in tasks})
    over_limit = sorted(b["batch_id"] for b in batches + shared_batches
                        if len(b["rule_ids"]) > rule_batch_size)
    dependency_errors = _dependency_errors(tasks)
    execution_batches, execution_coverage = _execution_batches(tasks, rule_batch_size)
    count_matches = diagnostics.get("blocked_count", len(blockers)) == len(blockers)
    coverage_valid = not (
        expected - set(assigned) or duplicates or unknown or not count_matches
        or unscheduled or duplicated_batch_tasks or foreign_batch_tasks
        or over_limit or dependency_errors or not execution_coverage["valid"]
    )
    return {
        "schema_version": 2,
        "blocker_signature": diagnostics.get("blocker_signature"),
        "work_counts": {p: categories[p] for p in WORK_ORDER},
        "rule_repair_tasks": tasks,
        "rule_work_matrix": matrix,
        "rule_repair_batches": batches,
        "shared_rule_repair_batches": shared_batches,
        "execution_batches": execution_batches,
        "rule_batch_size": rule_batch_size,
        "unscoped_task_ids": [t["task_id"] for t in tasks if not t["rule_ids"]],
        "task_coverage": {
            "blocker_total": len(blockers),
            "assigned_count": len(assigned),
            "missing_indexes": sorted(expected - set(assigned)),
            "duplicate_indexes": duplicates,
            "unclassified_indexes": unknown,
            "count_matches_diagnostic": count_matches,
            "affected_rule_count": len(owners_union),
            "task_count": len(tasks),
            "scheduled_task_count": len(batch_task_ids),
            "unscheduled_task_ids": unscheduled,
            "duplicate_batch_task_ids": duplicated_batch_tasks,
            "foreign_batch_task_ids": foreign_batch_tasks,
            "over_limit_batch_ids": over_limit,
            "dependency_errors": dependency_errors,
            "execution": execution_coverage,
            "valid": coverage_valid,
        },
        "read_only": True,
        "note": "僅 execution_batches 是具前置依賴順序的執行清單；rule_repair_batches／shared_rule_repair_batches 僅為工作分組。任務不代表來源已查核或准許整合。",
    }

def compare_rule_repair_diagnostics(before: dict[str, Any], after: dict[str, Any], *,
                                    max_new_blockers: int = 3) -> dict[str, Any]:
    """Read-only regression gate; caller must stop subsequent batches on pause."""
    if max_new_blockers < 0:
        raise ValueError("max_new_blockers 不可小於零")
    old = before.get("blockers", [])
    new = after.get("blockers", [])
    if not isinstance(old, list) or not isinstance(new, list):
        raise ValueError("blockers 必須是陣列")

    def key(b: dict) -> tuple:
        return (str(b.get("message", "")), tuple(sorted(b.get("rule_ids") or [])))

    earlier = {key(b) for b in old}
    current = {key(b) for b in new}
    additions = sorted(current - earlier)
    old_categories = {str(b.get("category", "other")) for b in old}
    new_categories = sorted({str(b.get("category", "other")) for b in new} - old_categories)
    old_work_items = {classify_repair_work(str(b.get("message", ""))) for b in old}
    new_work_items = sorted({classify_repair_work(str(b.get("message", "")))
                             for b in new} - old_work_items)
    unknown = sorted({str(b.get("message", "")) for b in new
                      if classify_repair_work(str(b.get("message", ""))) == "unclassified"})
    integrity = sorted({str(b.get("message", "")) for b in new
                        if b.get("category") == "integrity" or any(
                            x in str(b.get("message", ""))
                            for x in ("Journal", "Manifest", "快照已變更", "SHA256 不一致"))})
    reasons = []
    if new_categories or new_work_items:
        reasons.append("新增阻塞類型")
    if len(additions) > max_new_blockers:
        reasons.append(f"新增阻塞超過 {max_new_blockers} 筆")
    if unknown:
        reasons.append("含無法辨識的阻塞訊息")
    if integrity:
        reasons.append("出現完整性／來源快照錯誤")
    return {
        "before_signature": before.get("blocker_signature"),
        "after_signature": after.get("blocker_signature"),
        "new_blocker_count": len(additions),
        "removed_blocker_count": len(earlier - current),
        "new_categories": new_categories,
        "new_work_items": new_work_items,
        "unknown_messages": unknown,
        "integrity_messages": integrity,
        "pause_reasons": reasons,
        "should_pause": bool(reasons),
        "read_only": True,
        "note": "還須人工核對 Findings、來源 SHA256、Manifest/Journal；本函式不自動回退或放行。",
    }
