#!/usr/bin/env python3
"""完整與分類審查共用的逐條規則指引：補充標準對照、裁決指引與須載入的標準文件。

兩種佇列輸出相同欄位與順序；呼叫端以 rule_guidance.<名稱> 取用，測試請 patch 本模組。
"""
from __future__ import annotations

from adversarial_recheck import guidance as adversarial_guidance
from control_effectiveness import guidance as control_effectiveness_guidance
from decision_adjudication import guidance as decision_adjudication_guidance
from review_decision import load_decision_matrix
from standard_guides import STANDARD_GUIDES, load_owasp_2025_categories, load_tacert_v2_checks
from system_baseline import source_review_hints
from web_appendix1 import appendix_review_hints
from web_guide import web_guide_review_hints
from web_headers import header_review_hints


_MISSING = object()


def standard_maps(rules: list[dict]) -> dict[str, dict[str, list[dict]]]:
    """各補充標準對 70 項規則的對照；欄位順序即輸出順序。"""
    return {
        "tacert_v2_checks": load_tacert_v2_checks(rules),
        "owasp_2025_categories": load_owasp_2025_categories(rules),
        "system_baseline_v13_controls": source_review_hints(rules),
        "web_guide_v32_checks": web_guide_review_hints(rules),
        "web_guide_v32_appendix1": appendix_review_hints(rules),
        "web_guide_v32_appendix3": header_review_hints(rules),
    }


def guidance_fields(rule_id: str) -> dict[str, dict]:
    return {
        "control_effectiveness_guidance": control_effectiveness_guidance(rule_id),
        "decision_adjudication_guidance": decision_adjudication_guidance(rule_id),
        "adversarial_guidance": adversarial_guidance(rule_id),
    }


def shared_guidance() -> dict[str, dict]:
    """三種裁決指引中 70 條規則完全相同的欄位；批次輸出只送一次。

    依目前規則集即時計算，指引文字改變時自動重新分組，不維護手寫清單。
    """
    rule_ids = list(load_decision_matrix())
    per_rule = {rid: guidance_fields(rid) for rid in rule_ids}
    first = per_rule[rule_ids[0]]
    return {field: {key: value for key, value in values.items()
                    if all(per_rule[rid][field].get(key, _MISSING) == value for rid in rule_ids)}
            for field, values in first.items()}


def specific_guidance(rule_id: str, shared: dict[str, dict]) -> dict[str, dict]:
    """只保留該規則與共用指引不同、且未重複 decision_guidance 的欄位。"""
    decision = load_decision_matrix()[rule_id]
    return {field: {key: value for key, value in values.items()
                    if key not in shared.get(field, {}) and decision.get(key, _MISSING) != value}
            for field, values in guidance_fields(rule_id).items()}


def standard_documents(item: dict) -> list[str]:
    """只列出此規則實際有對照內容的標準文件，供 Agent 按需讀取。"""
    return [path for field, path in STANDARD_GUIDES.items() if item.get(field)]
