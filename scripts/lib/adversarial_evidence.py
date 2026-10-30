#!/usr/bin/env python3
"""第二輪反向複核的路徑、高風險規則清單與單筆證據核對；供複核與 Q4 品質守門共用。

本模組不得匯入 adversarial_recheck／adversarial_quality。
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from control_proofs import location_errors
from review_decision import is_weak_source_evidence
from review_snapshot import high_tier_rules
from review_core import ANALYSIS_ROOT

RELATIVE = ANALYSIS_ROOT
INDEX = RELATIVE / "structure-index.json"
SNAPSHOT = RELATIVE / "review-snapshot.json"
BASELINE = RELATIVE / "first-pass-baseline.json"
REVIEWS = RELATIVE / "adversarial-reviews.json"
HISTORY = RELATIVE / "second-pass-history"
# 高風險（inspection.review_tier=high）規則須提出兩種不同攻擊向量；清單以規則主檔為準。
HIGH_RISK_RULES = high_tier_rules()


def evidence_errors(target: Path, proof: Any, rid: str, label: str,
                     inspected: set[str], known: set[str], status: str,
                     audit: dict | None, formal_evidence: list[dict]) -> list[str]:
    if not isinstance(proof, dict):
        return [f"{rid}: {label} 缺少具體來源證據"]
    kind = proof.get("kind")
    if kind in {"source", "configuration"}:
        issues, _ = location_errors(target, known, inspected, proof, f"{rid}: {label}")
        if issues:
            return issues
        if is_weak_source_evidence(proof, target) is True:
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
