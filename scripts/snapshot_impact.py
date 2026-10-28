"""Conservative source-snapshot impact analysis; never decides security verdicts.

A narrow recheck is allowed only for modified, already indexed C# sources with
traceable rule ownership. Added/removed/configuration/unknown sources fail closed.
The source graph is candidate-only: its edges expand scope, never prove safety.
"""
from __future__ import annotations

from collections import defaultdict, deque
from typing import Any


def source_delta(before: dict[str, str], after: dict[str, str]) -> dict[str, list[str]]:
    return {
        "modified": sorted(p for p in before.keys() & after.keys() if before[p] != after[p]),
        "added": sorted(after.keys() - before.keys()),
        "removed": sorted(before.keys() - after.keys()),
    }


def affected_rules(
    old_hashes: dict[str, str], new_hashes: dict[str, str],
    index: dict[str, Any], assessment: dict[str, Any],
    closures: dict[str, Any], scopes: dict[str, str],
    current_candidates: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Return an auditable, conservative set of rules requiring new evidence."""
    delta = source_delta(old_hashes, new_hashes)
    changed = sorted(set().union(*map(set, delta.values())))
    all_rules = sorted(scopes)
    result: dict[str, Any] = {
        "changed_paths": changed,
        "source_delta": delta,
        "rule_ids": [],
        "full_recheck": False,
        "reason": "source-unchanged",
    }
    if not changed:
        return result

    def fallback(reason: str) -> dict[str, Any]:
        return {**result, "rule_ids": all_rules, "full_recheck": True, "reason": reason}

    # New/removed source, configuration and non-C# languages can change unseen
    # control responsibility. A candidate graph cannot exclude those changes.
    if delta["added"] or delta["removed"]:
        return fallback("source-inventory-changed")
    if any(not p.lower().endswith(".cs") for p in changed):
        return fallback("configuration-or-unsupported-source-changed")
    if (not isinstance(index, dict) or index.get("source_hashes") != old_hashes
            or not isinstance(index.get("rule_candidates"), dict)
            or not isinstance(index.get("typed_relationships"), list)
            or not isinstance(assessment.get("checks"), list)
            or not isinstance(closures, dict)):
        return fallback("missing-trustworthy-previous-index")

    candidates = index["rule_candidates"]
    if (not isinstance(current_candidates, dict)
            or any(path not in current_candidates
                   or not isinstance(current_candidates[path], list)
                   for path in changed)):
        return fallback("current-source-candidates-unavailable")
    graph: dict[str, set[str]] = defaultdict(set)
    for edge in index["typed_relationships"]:
        if not isinstance(edge, dict):
            return fallback("unrecognized-source-relationship")
        src, dst = edge.get("source"), edge.get("target")
        if not isinstance(src, str) or not isinstance(dst, str):
            return fallback("unrecognized-source-relationship")
        if src in old_hashes and dst in old_hashes:
            graph[src].add(dst)
            graph[dst].add(src)
    hints = index.get("cross_file_call_hints", {})
    if not isinstance(hints, dict):
        return fallback("unrecognized-callsite-index")
    for origin, calls in hints.items():
        if not isinstance(calls, list):
            return fallback("unrecognized-callsite-index")
        for call in calls:
            if not isinstance(call, dict) or not isinstance(call.get("possible_targets", []), list):
                return fallback("unrecognized-callsite-index")
            for item in call.get("possible_targets", []):
                if not isinstance(item, dict):
                    return fallback("unrecognized-callsite-index")
                dst = item.get("path")
                if origin in old_hashes and dst in old_hashes:
                    graph[origin].add(dst)
                    graph[dst].add(origin)

    involved = set(changed)
    queue = deque(changed)
    while queue:
        for adjacent in graph[queue.popleft()]:
            if adjacent not in involved:
                involved.add(adjacent)
                queue.append(adjacent)

    # A pre-indexed source must have a real rule owner. A search-hint miss is
    # never evidence that the changed code is irrelevant to security.
    owners: set[str] = set()
    for path in involved:
        hits = candidates.get(path, [])
        if not isinstance(hits, list):
            return fallback("unrecognized-rule-candidates")
        for hit in hits:
            if not isinstance(hit, dict):
                return fallback("unrecognized-rule-candidates")
            rid = hit.get("rule_id")
            if rid in scopes:
                owners.add(rid)

    for path in changed:
        for hit in current_candidates[path]:
            if not isinstance(hit, dict):
                return fallback("unrecognized-current-source-candidate")
            rid = hit.get("rule_id")
            if rid in scopes:
                owners.add(rid)

    for check in assessment["checks"]:
        if not isinstance(check, dict) or check.get("id") not in scopes:
            return fallback("invalid-assessment-scope")
        rid = check["id"]
        execution = check.get("execution") or {}
        if involved.intersection(execution.get("inspected_paths") or []):
            owners.add(rid)
        for ev in check.get("evidence") or []:
            if isinstance(ev, dict) and ev.get("path") in involved:
                owners.add(rid)
    for row in assessment.get("file_reviews") or []:
        if not isinstance(row, dict) or row.get("path") not in involved:
            continue
        for review in row.get("rule_reviews") or []:
            if isinstance(review, dict) and review.get("rule_id") in scopes:
                owners.add(review["rule_id"])
    for rid, closure in closures.items():
        if rid not in scopes or not isinstance(closure, dict):
            continue
        paths = set(closure.get("examined_paths") or [])
        trace = closure.get("control_trace") or {}
        if isinstance(trace, dict):
            paths.update(node.get("path") for node in trace.get("nodes", [])
                         if isinstance(node, dict))
        if paths & involved:
            owners.add(rid)

    if not owners:
        return fallback("changed-source-without-rule-ownership")
    # Whole-project controls must be reevaluated after any source change.
    owners.update(rid for rid, scope in scopes.items() if scope == "project")
    return {
        **result, "rule_ids": sorted(owners), "full_recheck": len(owners) == len(scopes),
        "reason": "tracked-source-relationship-closure",
        "related_paths": sorted(involved),
    }
