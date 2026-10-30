#!/usr/bin/env python3
"""P3 first-pass incremental *planning*; never grants a complete review or second pass.

All uncertain provenance or dependency edges expand to the entire 70-rule set.
Full gate still belongs to review_safety --begin-second-pass / authoritative diagnosis.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from review_safety import rule_scopes
from review_blockers import diagnose
from review_core import sha256_bytes as _sha, snapshot_fingerprint

BASE = Path("reports/security-code-review")
HIGH_RISK = frozenset(("AC", "AU", "IN", "CR"))
CONTRACT_FILES = (
    "rules.json", "policies/review-decision-matrix.json",
    "schemas/assessment.schema.json", "scripts/analysis_prepare.py",
    "scripts/snapshot_impact.py",
    "policies/evidence-relevance-features.json",
)

def _load(path: Path, fallback=None):
    if path.is_symlink():
        raise ValueError("增量驗證不接受 symbolic link")
    return json.loads(path.read_text("utf-8")) if path.is_file() else fallback


def contract_fingerprint(skill_root: Path, boundary_level: str) -> str:
    """Rule/feature/schema/analyser/boundary changes all invalidate an earlier plan."""
    if boundary_level not in ("L1", "L2", "L3"):
        raise ValueError("隔離等級不合法")
    h = hashlib.sha256(boundary_level.encode("ascii"))
    for item in CONTRACT_FILES:
        path = skill_root / item
        # The optional E2 policy is also tracked as absent; its future addition invalidates cache.
        raw = path.read_bytes() if path.is_file() else b"<absent>"
        h.update(item.encode("utf-8") + b"\0" + _sha(raw).encode("ascii") + b"\0")
    return h.hexdigest()

def _paths_from_trace(trace) -> set[str]:
    if not isinstance(trace, dict):
        raise ValueError("無法驗證 control_trace")
    nodes = trace.get("nodes") or []
    if not isinstance(nodes, list):
        raise ValueError("control_trace 節點不是陣列")
    result = set()
    for node in nodes:
        if not isinstance(node, dict) or not isinstance(node.get("path"), str):
            raise ValueError("control_trace 節點缺來源路徑")
        result.add(node["path"])
    return result

def plan(target: Path, changes: dict[str, Any], *, previous_contract: str | None = None,
         previous_snapshot: str | None = None,
         boundary_level: str = "L3", sample_count: int = 8, seed: str = "p3-v1") -> dict:
    """Return a conservative recheck set; does not edit evidence or claim pass."""
    target = target.resolve()
    scopes = rule_scopes()
    all_rules = sorted(scopes)
    snapshot = _load(target / BASE / "analysis/review-snapshot.json", {})
    index = _load(target / BASE / "analysis/structure-index.json", {})
    assessment = _load(target / BASE / "assessment.json", {})
    closures = _load(target / BASE / "analysis/rule-closures.json", {})
    contract = contract_fingerprint(Path(__file__).resolve().parents[1], boundary_level)
    base = {
        "schema_version": 1, "verification_kind": "incremental-plan",
        "incremental_clean": False, "full_gate_passed": False,
        "ready_for_second_pass": False, "contract_fingerprint": contract,
        "boundary_level": boundary_level, "source_fingerprint": None,
        "affected_rules": [], "sample_rules": [],
        "full_recheck": True, "reason": "unverified-dependencies"
    }
    def all_scope(reason):
        return {**base, "full_recheck": True, "reason": reason,
                "affected_rules": all_rules, "sample_rules": []}
    if not isinstance(changes, dict):
        return all_scope("invalid-change-contract")
    allowed = {"changed_paths", "changed_rule_ids", "changed_artifacts", "recently_repaired_rule_ids"}
    if set(changes) - allowed:
        return all_scope("unknown-change-dimension")
    path_changes = changes.get("changed_paths") or []
    rule_changes = changes.get("changed_rule_ids") or []
    artifacts = changes.get("changed_artifacts") or []
    recent_changes = changes.get("recently_repaired_rule_ids") or []
    if any(not isinstance(x, list) for x in (path_changes, rule_changes, artifacts, recent_changes)):
        return all_scope("invalid-change-list")
    if any(not isinstance(x, str) for x in (*path_changes, *rule_changes, *artifacts, *recent_changes)):
        return all_scope("invalid-change-entry")
    paths, rules = set(path_changes), set(rule_changes)
    if not paths and not rules and not artifacts:
        return all_scope("missing-proven-change")
    if not rules <= set(all_rules) or not set(recent_changes) <= set(all_rules):
        return all_scope("unknown-rule")
    # No formal per-artifact diff receipt exists yet. Even a known sidecar can
    # affect a rule outside the declared list, so always broaden to all rules.
    if artifacts:
        return all_scope("unproven-artifact-impact")
    if previous_contract is None or previous_contract != contract:
        return all_scope("contract-or-boundary-version-changed")
    if (not isinstance(snapshot, dict) or previous_snapshot is None
            or previous_snapshot != snapshot_fingerprint(snapshot)):
        return all_scope("source-snapshot-version-changed")
    hashes = snapshot.get("source_hashes") if isinstance(snapshot, dict) else None
    if (not isinstance(hashes, dict) or not all(isinstance(k, str) and isinstance(v, str)
                                                for k, v in hashes.items())):
        return all_scope("untrusted-source-snapshot")
    base["source_fingerprint"] = _sha(json.dumps(hashes, sort_keys=True).encode("utf-8"))
    # Any changed source version needs a fresh authoritative source-impact analysis,
    # not an evidence-only cache.
    if any(p not in hashes for p in paths):
        return all_scope("new-or-removed-source")
    if not isinstance(index, dict) or index.get("source_hashes") != hashes:
        return all_scope("index-snapshot-mismatch")
    if (not isinstance(index.get("typed_relationships"), list)
            or not isinstance(index.get("cross_file_call_hints"), dict)
            or not isinstance(assessment.get("checks"), list)
            or not isinstance(assessment.get("file_reviews"), list)
            or not isinstance(closures, dict)):
        return all_scope("incomplete-dependency-graph")
    # A partial rule set is never a reliable absence-of-dependency proof.
    checks = assessment["checks"]
    if len(checks) != len(all_rules) or {c.get("id") for c in checks if isinstance(c, dict)} != set(all_rules):
        return all_scope("incomplete-dependency-graph")
    graph: dict[str, set[str]] = defaultdict(set)
    try:
        for edge in index["typed_relationships"]:
            a, b = edge["source"], edge["target"]
            if not isinstance(a, str) or not isinstance(b, str):
                raise ValueError
            if a not in hashes or b not in hashes:
                raise ValueError
            graph[a].add(b)
            graph[b].add(a)
        for origin, calls in index["cross_file_call_hints"].items():
            if origin not in hashes or not isinstance(calls, list):
                raise ValueError
            for call in calls:
                if not isinstance(call, dict):
                    raise ValueError
                possible = call.get("possible_targets")
                if not isinstance(possible, list):
                    raise ValueError
                for dest in possible:
                    p = dest.get("path") if isinstance(dest, dict) else None
                    if not isinstance(p, str) or p not in hashes:
                        raise ValueError
                    graph[origin].add(p)
                    graph[p].add(origin)
    except (KeyError, TypeError, ValueError):
        return all_scope("unresolved-callgraph-edges")
    owners: dict[str, set[str]] = defaultdict(set)
    rule_paths: dict[str, set[str]] = defaultdict(set)
    try:
        for check in assessment["checks"]:
            rid = check["id"]
            if rid not in scopes:
                raise ValueError
            listed = (check.get("execution") or {}).get("inspected_paths") or []
            evidence = check.get("evidence") or []
            if not isinstance(listed, list) or not isinstance(evidence, list):
                raise ValueError
            linked = set(listed)
            linked.update(e["path"] for e in evidence if isinstance(e, dict) and isinstance(e.get("path"), str))
            rule_paths[rid].update(linked)
        for row in assessment["file_reviews"]:
            p = row["path"]
            for rr in row.get("rule_reviews") or []:
                if not isinstance(rr, dict) or rr.get("rule_id") not in scopes:
                    raise ValueError
                rule_paths[rr["rule_id"]].add(p)
        for rid, closure in closures.items():
            if rid not in scopes or not isinstance(closure, dict):
                raise ValueError
            listed = closure.get("examined_paths") or []
            if not isinstance(listed, list):
                raise ValueError
            rule_paths[rid].update(listed)
            if closure.get("control_trace") is not None:
                rule_paths[rid].update(_paths_from_trace(closure["control_trace"]))
        for rid, linked in rule_paths.items():
            for p in linked:
                if not isinstance(p, str) or p not in hashes:
                    raise ValueError
                owners[p].add(rid)
    except (KeyError, ValueError, TypeError):
        return all_scope("untrusted-rule-evidence-links")
    affected_paths = set(paths)
    frontier = deque(paths)
    while frontier:
        for adjacent in graph[frontier.popleft()]:
            if adjacent not in affected_paths:
                affected_paths.add(adjacent)
                frontier.append(adjacent)
    for rid in rules:
        affected_paths.update(rule_paths[rid])
    # Re-expand cross-file dependencies after the initial rule-to-file expansion.
    frontier = deque(affected_paths)
    while frontier:
        for adjacent in graph[frontier.popleft()]:
            if adjacent not in affected_paths:
                affected_paths.add(adjacent)
                frontier.append(adjacent)
    affected = rules | {rid for p in affected_paths for rid in owners[p]}
    affected.update(rid for rid, scope in scopes.items() if scope == "project")
    if not affected or paths and any(not owners[p] for p in affected_paths):
        return all_scope("path-without-verified-rule-owner")
    # High-risk-biased deterministic independent full comparison sample.
    pool = set(all_rules) - affected
    trace_rules = {rid for rid, closure in closures.items()
                   if isinstance(closure, dict) and isinstance(closure.get("control_trace"), dict)
                   and (closure["control_trace"].get("nodes") or [])}
    repaired = set(recent_changes)
    shared_fanout = {rid: sum(max(0, len(owners[p]) - 1) for p in linked)
                     for rid, linked in rule_paths.items()}
    rank = lambda rid: (0 if rid.split("-")[0] in HIGH_RISK else 1,
                        0 if rid in repaired else 1,
                        0 if rid in trace_rules else 1,
                        -shared_fanout.get(rid, 0),
                        hashlib.sha256((seed + rid).encode("utf-8")).hexdigest())
    sample = sorted(pool, key=rank)[:max(0, sample_count)]
    return {**base, "full_recheck": len(affected) == len(all_rules),
            "reason": "tracked-evidence-and-callgraph",
            "affected_rules": sorted(affected), "affected_paths": sorted(affected_paths),
            "sample_rules": sample, "sample_seed": seed,
            "sample_policy": "high-risk, recently-repaired, trace endpoints, shared-source fanout",
            "sampling_note": "sample is a diagnostic cross-check, never substitutes for final full gate"}

def full_comparison(target: Path, plan_data: dict, *, selected_blocker_ids: list[str] | None = None):
    """Actual authoritative full diagnosis; a missing blocker owner always invalidates incremental scope."""
    target = target.resolve()
    if (not isinstance(plan_data, dict) or plan_data.get("verification_kind") != "incremental-plan"
            or plan_data.get("full_recheck") is not False):
        return {"incremental_clean": False, "full_gate_passed": False,
                "ready_for_second_pass": False, "reason": "requires-full-recheck"}
    current_contract = contract_fingerprint(Path(__file__).resolve().parents[1],
                                            plan_data.get("boundary_level", "INVALID"))
    current_snapshot = _load(target / BASE / "analysis/review-snapshot.json", {})
    hashes = current_snapshot.get("source_hashes") if isinstance(current_snapshot, dict) else None
    current_source = (_sha(json.dumps(hashes, sort_keys=True).encode("utf-8"))
                      if isinstance(hashes, dict) else None)
    if (plan_data.get("contract_fingerprint") != current_contract
            or current_source != plan_data.get("source_fingerprint")):
        return {"incremental_clean": False, "full_gate_passed": False,
                "ready_for_second_pass": False, "reason": "incremental-cache-invalidated"}
    assessment = _load(target / BASE / "assessment.json")
    if not isinstance(assessment, dict):
        raise ValueError("正式 assessment 不存在")
    from evidence_integrity import errors as integrity_errors
    from review_safety import snapshot_errors
    integrity = integrity_errors(target) + snapshot_errors(target)
    diagnostics = diagnose(target, assessment)
    scope = set(plan_data["affected_rules"]) | set(plan_data["sample_rules"])
    unknown = []
    for blocker in diagnostics["blockers"]:
        ids = blocker.get("rule_ids") or []
        if not ids or not set(ids) <= scope:
            unknown.append(blocker.get("category", "other"))
    return {"incremental_clean": not unknown and not integrity and diagnostics["blocked_count"] == 0,
            # This is a comparison, *never* a successful formal first-pass gate.
            "full_gate_passed": False, "ready_for_second_pass": False,
            "unexpected_full_blocker_categories": sorted(set(unknown)),
            "full_blocked_count": diagnostics["blocked_count"],
            "source_integrity_errors": len(integrity),
            "reason": "untracked-dependency" if unknown else "full-comparison-complete"}

def main():
    p = argparse.ArgumentParser(description="P3 保守增量工作範圍，不輸出正式 Pass")
    p.add_argument("--target", required=True, type=Path)
    p.add_argument("--changes", required=True, type=Path)
    p.add_argument("--previous-contract")
    p.add_argument("--previous-snapshot", help="上次可信來源快照的 snapshot_fingerprint")
    p.add_argument("--boundary-level", choices=("L1", "L2", "L3"), default="L3")
    p.add_argument("--sample-count", type=int, default=8)
    p.add_argument("--seed", default="p3-v1")
    p.add_argument("--compare-full", action="store_true")
    args = p.parse_args()
    try:
        changes = _load(args.changes)
        result = plan(args.target, changes, previous_contract=args.previous_contract,
                      previous_snapshot=args.previous_snapshot,
                      boundary_level=args.boundary_level,
                      sample_count=args.sample_count, seed=args.seed)
        if args.compare_full:
            result["full_comparison"] = full_comparison(args.target, result)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if not result["full_recheck"] else 1
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        p.exit(2, "P3 增量範圍不可信：" + str(exc) + "\n")

if __name__ == "__main__":
    raise SystemExit(main())
