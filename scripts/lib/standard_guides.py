#!/usr/bin/env python3
"""補充標準（TACERT V2、OWASP Top 10:2025）對照載入與標準文件路徑；供完整與分類審查共用。"""
from __future__ import annotations

from pathlib import Path

import yaml

SKILL_ROOT = Path(__file__).resolve().parents[1]
TACERT_V2_FILE = SKILL_ROOT / "standards" / "tacert-v2-checklist.yaml"
OWASP_2025_FILE = SKILL_ROOT / "standards" / "owasp-top10-2025.yaml"


def load_owasp_2025_categories(rules: list[dict]) -> dict[str, list[dict]]:
    """將 OWASP Top 10:2025 官方分類對應至 70 項規則（非符合判定）。"""
    document = yaml.safe_load(OWASP_2025_FILE.read_text(encoding="utf-8"))
    mapped = {rule["id"]: [] for rule in rules}
    for category in document["categories"]:
        for rid in category["related_rule_ids"]:
            if rid not in mapped:
                raise ValueError(f"OWASP 2025 分類對應未知規則：{rid}")
            mapped[rid].append({
                "id": category["id"],
                "title": category["title"],
                "review_steps": category["review_steps"],
                "coverage_gap": category["coverage_gap"],
                "source_url": category["url"],
                "mapping_type": category["mapping_type"],
            })
    return mapped


def load_tacert_v2_checks(rules: list[dict]) -> dict[str, list[dict]]:
    """將 TACERT V2 各補充要求掛到既有規則；不變更 70 項身分與進度模型。"""
    data = yaml.safe_load(TACERT_V2_FILE.read_text(encoding="utf-8"))
    mapped = {rule["id"]: [] for rule in rules}
    for entry in data["checks"]:
        for rid in entry["related_rule_ids"]:
            if rid not in mapped:
                raise ValueError(f"TACERT V2 檢核對應未知規則：{rid}")
            mapped[rid].append({
                "id": entry["id"], "title": entry["title"],
                "pdf_page": entry["pdf_page"],
                "verification_mode": entry["verification_mode"],
                "review_steps": entry["review_steps"],
                "expected_evidence": entry["expected_evidence"],
            })
    return mapped


# 與 SKILL.md「標準文件按需載入」一致；路徑一律相對 SKILL_ROOT。
STANDARD_GUIDES = {
    "tacert_v2_checks": "docs/tacert-v2-review.md",
    "owasp_2025_categories": "docs/owasp-top10-2025-review.md",
    "system_baseline_v13_controls": "docs/system-baseline-v1.3-review.md",
    "web_guide_v32_checks": "docs/web-guide-v3.2-review.md",
    "web_guide_v32_appendix1": "docs/web-guide-v3.2-appendix1-review.md",
    "web_guide_v32_appendix3": "docs/web-guide-v3.2-appendix3-review.md",
}
