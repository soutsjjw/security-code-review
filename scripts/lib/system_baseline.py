"""《資通系統防護基準驗證實務》V1.3 的獨立第二層驗證。

80 項正式控制措施不會自動由 70 項程式碼規則推定符合。
僅在有明確防護需求分級及獨立證據時，才接受人工驗證的 pass/fail。
"""
from __future__ import annotations

from collections import Counter
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
CATALOG_PATH = ROOT / "standards" / "tw-system-baseline-v1.3.yaml"
LEVELS = ("普", "中", "高")
DECISIONS = ("pass", "fail", "review", "na")
PENDING = ("pending_level", "not_assessed", "not_applicable_by_level")


def load_catalog(path: Path = CATALOG_PATH) -> list[dict]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    rows = document["controls"]
    ids = [r["id"] for r in rows]
    if document.get("version") != "V1.3" or len(rows) != 80 or len(ids) != len(set(ids)):
        raise ValueError("防護基準控制清冊須為 V1.3 共 80 個不重複 ID")
    if [sum(level in r["applicable_levels"] for r in rows) for level in LEVELS] != [45, 62, 80]:
        raise ValueError("防護基準適用項數必須為普 45／中 62／高 80")
    for row in rows:
        if (row["verification_mode"] not in ("source", "hybrid", "external")
                or row["mapping_type"] != "related_control_not_equivalent"
                or not row["title"] or not row["source_section"]
                or not row["expected_evidence"]):
            raise ValueError("防護基準清冊資料不完整：" + row["id"])
    return rows


def source_review_hints(rules: list[dict]) -> dict[str, list[dict]]:
    """與 70 項一對多相關映射；是審查提示而非合規判定。"""
    mapped: dict[str, list[dict]] = {r["id"]: [] for r in rules}
    for control in load_catalog():
        for rid in control["related_rule_ids"]:
            if rid not in mapped:
                raise ValueError(f"防護基準指向不存在的原始碼規則：{rid}")
            mapped[rid].append({
                "id": control["id"], "section": control["source_section"],
                "title": control["title"], "pdf_page": control["pdf_page"],
                "applicable_levels": control["applicable_levels"],
                "verification_mode": control["verification_mode"],
                "review_focus": control["review_focus"],
                "expected_evidence": control["expected_evidence"],
            })
    return mapped


def _normalize_review_entries(review: dict | None) -> dict[str, dict]:
    if not review:
        return {}
    if not isinstance(review, dict) or not isinstance(review.get("controls"), list):
        raise ValueError("baseline_assessment.json 須包含 controls 陣列")
    indexed: dict[str, dict] = {}
    for item in review["controls"]:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise ValueError("防護基準審核結果須有 ID")
        rid = item["id"]
        if rid in indexed:
            raise ValueError("防護基準審核結果重複：" + rid)
        if item.get("status") not in DECISIONS:
            raise ValueError(f"{rid}: 禁止以 pending 或系統自動結果作為人工審核結果")
        if not str(item.get("reason", "")).strip() or not str(item.get("reviewer", "")).strip():
            raise ValueError(f"{rid}: 人工審核需有判定理由與審核者")
        try:
            date.fromisoformat(item["verified_on"])
        except (TypeError, KeyError, ValueError) as exc:
            raise ValueError(f"{rid}: 須提供有效 verified_on 日期") from exc
        evidence = item.get("evidence", [])
        if not isinstance(evidence, list) or any(not isinstance(e, str) or not e.strip() for e in evidence):
            raise ValueError(f"{rid}: evidence 須為非空證據參照字串陣列")
        if item["status"] in ("pass", "fail") and not evidence:
            raise ValueError(f"{rid}: pass/fail 必須具有可核對的獨立證據")
        indexed[rid] = {
            "status": item["status"], "reason": item["reason"],
            "reviewer": item["reviewer"], "verified_on": item["verified_on"],
            "evidence": evidence,
        }
    return indexed


def review_from_report(payload: dict) -> dict:
    """當 --report 重新生成時保留已記錄的人工審核，不覆寫為未知。"""
    items = []
    for item in payload.get("controls", []):
        if item.get("status") in DECISIONS:
            items.append({k: item[k] for k in
                          ("id", "status", "reason", "reviewer", "verified_on", "evidence")})
    return {"controls": items}


def build_system_baseline(project: dict, review: dict | None = None) -> dict:
    level = project.get("protection_demand_level", "待確認")
    if level not in (*LEVELS, "待確認"):
        raise ValueError("系統防護需求分級僅接受普／中／高／待確認")
    basis = str(project.get("protection_demand_level_basis", "")).strip()
    if level in LEVELS and not basis:
        raise ValueError("普／中／高分級須提供 protection_demand_level_basis，不能以 A～E 責任等級換算")
    indexed = _normalize_review_entries(review)
    catalog = load_catalog()
    known_ids = {c["id"] for c in catalog}
    if set(indexed) - known_ids:
        raise ValueError("防護基準審核結果包含未知 ID：" + ", ".join(sorted(set(indexed) - known_ids)))
    output = []
    for item in catalog:
        applicable = None if level == "待確認" else level in item["applicable_levels"]
        answer = indexed.get(item["id"])
        if answer and applicable is not True:
            raise ValueError(f"{item['id']}: 未有適用分級或不屬於該級，不能填人工驗證結論")
        status = answer["status"] if answer else (
            "pending_level" if applicable is None else
            "not_assessed" if applicable else "not_applicable_by_level"
        )
        entry = {
            "id": item["id"], "section": item["source_section"],
            "domain": item["domain"], "title": item["title"],
            "pdf_page": item["pdf_page"],
            "applicable_levels": item["applicable_levels"],
            "verification_mode": item["verification_mode"],
            "related_rule_ids": item["related_rule_ids"],
            "expected_evidence": item["expected_evidence"],
            "applicable": applicable, "status": status,
        }
        if answer:
            entry.update(answer)
        output.append(entry)
    counts = Counter(e["status"] for e in output)
    return {
        "standard_id": "TW-SYSTEM-PROTECTION-BASELINE",
        "version": "V1.3", "revision_date": "2026-06-03",
        "source_title": "資通系統防護基準驗證實務",
        "demand_level": level, "demand_level_basis": basis,
        "total_controls": 80,
        "applicable_controls": None if level == "待確認" else sum(e["applicable"] for e in output),
        "status_counts": dict(counts),
        "assessment_note": "此為獨立防護基準控制措施驗證，未提供獨立證據的項目不是符合；亦不可由原 70 項 Pass 推定符合。",
        "controls": output,
    }


def validate_system_baseline(project: dict, payload: dict) -> list[str]:
    """重新產生正規化內容並逐項比對，拒絕偽造項目數、判定及摘要。"""
    try:
        reconstructed = build_system_baseline(project, review_from_report(payload))
        if reconstructed != payload:
            return ["system_baseline 與 V1.3 清冊、分級或審核證據不一致"]
    except (KeyError, TypeError, ValueError) as exc:
        return [f"system_baseline 無效：{exc}"]
    return []
