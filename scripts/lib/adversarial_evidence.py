#!/usr/bin/env python3
"""第二輪反向複核的路徑、高風險規則清單與單筆證據核對；供複核與 Q4 品質守門共用。

本模組不得匯入 adversarial_recheck／adversarial_quality。
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from control_proofs import _location_errors
from review_decision import _is_weak_source_evidence

RELATIVE = Path("reports/security-code-review/analysis")
INDEX = RELATIVE / "structure-index.json"
SNAPSHOT = RELATIVE / "review-snapshot.json"
BASELINE = RELATIVE / "first-pass-baseline.json"
REVIEWS = RELATIVE / "adversarial-reviews.json"
HISTORY = RELATIVE / "second-pass-history"
HIGH_RISK_RULES = frozenset({
    "AC-01", "AC-02", "AC-04", "AC-06", "AC-08",
    "AU-03", "AU-06", "AU-08", "AU-09",
    "IN-01", "IN-02", "IN-03", "IN-04", "IN-06", "IN-07", "IN-08",
    "CR-01", "CR-02", "CR-03", "CR-05", "CR-06", "PD-02", "PD-06",
})


def _evidence_errors(target: Path, proof: Any, rid: str, label: str,
                     inspected: set[str], known: set[str], status: str,
                     audit: dict | None, formal_evidence: list[dict]) -> list[str]:
    if not isinstance(proof, dict):
        return [f"{rid}: {label} 缺少具體來源證據"]
    kind = proof.get("kind")
    if kind in {"source", "configuration"}:
        issues, _ = _location_errors(target, known, inspected, proof, f"{rid}: {label}")
        if issues:
            return issues
        if _is_weak_source_evidence(proof, target) is True:
            return [f"{rid}: {label} 只有宣告、using 或註解，不能證明反例"]
        return []
    if kind == "external_gap" and status == "review":
        gap = (audit or {}).get("external_gap")
        artifact = gap.get("artifact") if isinstance(gap, dict) else None
        if not isinstance(artifact, str) or proof.get("artifact") != artifact:
            return [f"{rid}: {label} 外部缺口須對應正式判定的具體待確認工件"]
        return []
    if kind == "external_artifact":
        reference = proof.get("artifact_id")
        if (not isinstance(reference, str) or not reference.strip()
                or not any(isinstance(item, dict) and item.get("artifact_id") == reference
                           and item.get("kind") in {"deployment", "operating_record", "policy",
                                                    "scan", "test", "interview"}
                           for item in formal_evidence)):
            return [f"{rid}: {label} 外部工件必須引用正式檢核中已存在的工件識別碼"]
        return []
    return [f"{rid}: {label} 缺少有效 source / configuration / external_gap / external_artifact 證據"]
