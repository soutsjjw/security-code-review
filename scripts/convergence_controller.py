#!/usr/bin/env python3
"""P4-B: finite, auditable blocker-strategy recommendations; no arbitrary Run cutoff.

A strategy is identified by normalized root cause, evidence kind and fixed steps.
A mere renamed strategy cannot reset attempt history. Exhaustion blocks a work
group only as a diagnosis; the Run and unrelated work remain executable.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from review_blockers import FIXES, diagnose
import review_log

# Each strategy changes the actual type/verification of evidence; none fabricates evidence.
STRATEGIES = {
    "file_review_links": [
        ("source-read", ("read-source", "validate-file-rule-links")),
        ("relation-audit", ("read-callsite", "recheck-inspected-paths")),
    ],
    "control_trace": [
        ("source-read", ("read-source", "trace-controller-to-operation")),
        ("callsite-verify", ("read-callsite", "reconcile-typed-relations")),
    ],
    "cross_file_candidates": [
        ("callsite-verify", ("read-callsite", "resolve-target-symbol")),
        ("source-read", ("read-source", "verify-runtime-wiring")),
    ],
    "integrity": [
        ("journal-audit", ("verify-journal", "recover-legal-transaction")),
        ("snapshot-audit", ("verify-snapshot", "recheck-source-hashes")),
    ],
    "weak_source_evidence": [
        ("source-read", ("read-source", "verify-control-effect")),
        ("counterexample", ("read-source", "verify-bypass-path")),
    ],
    "unrelated_evidence": [
        ("source-read", ("read-source", "relink-supported-rule")),
        ("counterexample", ("read-source", "verify-contradiction")),
    ],
    "control_outcome": [
        ("source-read", ("read-source", "trace-failure-branch")),
        ("counterexample", ("read-source", "verify-control-bypass")),
    ],
    "incomplete_static": [
        ("source-read", ("read-source", "complete-static-analysis")),
        ("configuration", ("read-configuration", "verify-runtime-binding")),
    ],
    "missing_external_decision": [
        ("external-proof", ("request-evidence", "verify-decision-outcomes")),
    ],
    "delegation_unverified": [
        ("external-proof", ("request-evidence", "verify-ownership")),
    ],
    "other": [
        ("source-read", ("read-source", "reclassify-authoritative-blocker")),
    ],
}

def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                    separators=(",", ":")).encode("utf-8")).hexdigest()

def strategy_signature(category, evidence_kind, steps, scope_rules):
    if category not in FIXES or not isinstance(steps, (tuple, list)):
        raise ValueError("未支援的策略")
    return _digest({"category": category, "evidence_kind": evidence_kind,
                    "steps": list(steps), "rules": sorted(scope_rules)})

def _options(category, rules):
    return [{"id": category + ":" + method,
             "category": category, "evidence_kind": method,
             "steps": list(steps), "rules": sorted(rules),
             "signature": strategy_signature(category, method, steps, rules)}
            for method, steps in STRATEGIES.get(category, STRATEGIES["other"])]

def evaluate(previous: dict, diagnostics: dict, *, k: int = 3, m: int = 3) -> dict:
    """Pure transition: retry thresholds only trigger diagnosis, never Run termination."""
    if type(k) is not int or type(m) is not int or k < 1 or m < 1:
        raise ValueError("K/M 必須為正整數")
    if not isinstance(diagnostics, dict) or not isinstance(diagnostics.get("blockers"), list):
        raise ValueError("缺少權威 Blocker 診斷")
    prev = previous if isinstance(previous, dict) else {}
    fingerprint = diagnostics.get("blocker_signature")
    if not isinstance(fingerprint, str) or len(fingerprint) != 64:
        raise ValueError("Blocker 指紋格式無效")
    count = diagnostics.get("blocked_count")
    if type(count) is not int or count < 0:
        raise ValueError("Blocked 計數無效")
    prev_count = prev.get("count")
    prev_sig = prev.get("signature")
    same = prev_sig == fingerprint
    # A falling count with a different signature is improvement. Same count with
    # different fingerprints isn't necessarily improvement: don't reset stall.
    improved = prev_count is None or count < prev_count
    unchanged = 0 if improved else int(prev.get("nonprogress_batches", 0)) + 1
    repeated = (int(prev.get("repeat_count", 0)) + 1) if same else 1
    attempts = dict(prev.get("attempts") or {})
    groups = []
    for group in diagnostics.get("root_cause_groups") or []:
        cat = group.get("category")
        if cat not in FIXES:
            cat = "other"
        rules = group.get("rule_ids") or []
        if not isinstance(rules, list) or any(not isinstance(x, str) for x in rules):
            raise ValueError("策略缺少規則關聯")
        available = _options(cat, rules)
        key = _digest({"category": cat, "rules": sorted(rules), "signature": fingerprint})
        used = set(attempts.get(key, []))
        remaining = [o for o in available if o["signature"] not in used]
        groups.append({"category": cat, "rule_ids": sorted(rules),
                       "blocker_count": group["blocker_count"], "group_key": key,
                       "remaining_strategies": remaining,
                       "attempted_signatures": sorted(used),
                       "strategy_exhausted": not remaining})
    needs_diagnosis = count > 0 and (unchanged >= k or repeated >= m)
    status = ("running" if count == 0 or not needs_diagnosis else
              "diagnosing" if any(g["remaining_strategies"] for g in groups) else
              "exhausted_requires_evidence")
    return {"schema_version": 1, "status": status, "signature": fingerprint,
            "count": count, "nonprogress_batches": unchanged,
            "repeat_count": repeated, "attempts": attempts, "groups": groups,
            "diagnostic_trigger": needs_diagnosis,
            "block_entire_run": False,
            "threshold_note": "K/M are provisional diagnostic triggers, not acceptance or termination limits"}

def record_attempt(state: dict, *, category: str, group_key: str, strategy_id: str,
                   evidence_receipt: str):
    """Write-only evidence-independent attempt ledger. Does not claim resolution."""
    if not isinstance(evidence_receipt, str) or not evidence_receipt.strip():
        raise ValueError("每次策略嘗試須提供可追溯的證據收據識別")
    matches = [g for g in state["groups"] if g["group_key"] == group_key and g["category"] == category]
    if len(matches) != 1:
        raise ValueError("策略群組版本已變更；須重新診斷")
    option = next((o for o in matches[0]["remaining_strategies"] if o["id"] == strategy_id), None)
    if option is None or option["signature"] in set(state.get("attempts", {}).get(group_key, [])):
        raise ValueError("同一簽章策略已嘗試或不受支援")
    updated = dict(state)
    attempts = {k: list(v) for k, v in state["attempts"].items()}
    attempts.setdefault(group_key, []).append(option["signature"])
    updated["attempts"] = attempts
    updated["status"] = "strategy_changed"
    updated["strategy_history"] = list(state.get("strategy_history") or []) + [{
        "group_key": group_key, "category": category,
        "strategy_signature": option["signature"],
        "receipt_fingerprint": _digest(evidence_receipt),
        "blocker_signature": state["signature"],
    }]
    return updated


def observe_diagnostics(target: Path, diagnostics: dict, *, k=3, m=3):
    """Reuse the same authoritative diagnosis instead of calling the full validator twice."""
    target = target.resolve()
    folder, latest = review_log._paths(target)
    current = review_log._load(latest)
    if not current or current.get("status") != "running":
        raise ValueError("無有效 running Run；收斂觀測不會自動開啟新 Run")
    state = evaluate(current.get("convergence") or {}, diagnostics, k=k, m=m)
    current["convergence"] = state
    review_log._append(folder, current, "convergence_observed", "first_pass",
                       metrics={"blocked_count": state["count"],
                                "nonprogress_batches": state["nonprogress_batches"],
                                "strategy_exhausted_groups": sum(g["strategy_exhausted"] for g in state["groups"])})
    review_log._save(folder, current)
    return state

def run(target: Path, *, category=None, group_key=None, strategy_id=None, receipt=None,
        k=3, m=3):
    target = target.resolve()
    folder, latest = review_log._paths(target)
    observed = review_log._load(latest)
    if not observed or observed.get("status") not in ("running", "stalled"):
        raise ValueError("請先建立有效 Run；此命令不會啟動新審查")
    assessment = target / "reports/security-code-review/assessment.json"
    if not assessment.is_file():
        raise ValueError("尚無正式 assessment")
    diagnostics = diagnose(target, json.loads(assessment.read_text("utf-8")))
    state = evaluate(observed.get("convergence") or {}, diagnostics, k=k, m=m)
    if strategy_id is not None:
        if not all((category, group_key, receipt)):
            raise ValueError("需提供策略類別、群組與證據收據識別")
        state = record_attempt(state, category=category, group_key=group_key,
                               strategy_id=strategy_id, evidence_receipt=receipt)
    observed["convergence"] = state
    review_log._append(folder, observed, "convergence_observed", "first_pass",
                       metrics={"blocked_count": state["count"],
                                "nonprogress_batches": state["nonprogress_batches"],
                                "strategy_exhausted_groups": sum(g["strategy_exhausted"] for g in state["groups"])})
    review_log._save(folder, observed)
    return state

def main():
    parser = argparse.ArgumentParser(description="P4-B 無效循環檢測及可追溯策略切換")
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--category")
    parser.add_argument("--group-key")
    parser.add_argument("--strategy-id")
    parser.add_argument("--evidence-receipt")
    parser.add_argument("--k", type=int, default=3)
    parser.add_argument("--m", type=int, default=3)
    a = parser.parse_args()
    try:
        output = run(a.target, category=a.category, group_key=a.group_key,
                     strategy_id=a.strategy_id, receipt=a.evidence_receipt, k=a.k, m=a.m)
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        parser.exit(2, "P4-B 收斂診斷失敗：" + str(exc) + "\n")

if __name__ == "__main__":
    raise SystemExit(main())
