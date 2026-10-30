"""WEB 應用程式安全參考指引 V3.2－附件 1（55 項）查檢對照。

與原 70 項程式碼規則、V1.3 80 項系統防護基準分開。
關聯規則之 Pass/Fail 不自動構成附件『是否符合』的證明。
"""
from __future__ import annotations

from collections import Counter
from datetime import date
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "standards" / "nics-web-v3.2-appendix1.yaml"
LEVELS = ("普", "中", "高")
VERIFIED_STATES = ("pass", "fail", "review", "na")


def load_appendix1(rules: list[dict]) -> dict:
    data = yaml.safe_load(CATALOG.read_text(encoding="utf-8"))
    entries = data.get("checks", [])
    ids = [entry.get("id") for entry in entries]
    if (data.get("standard_id") != "NICS-WEB-GUIDE-APPENDIX1"
            or data.get("guide_version") != "V3.2"
            or len(entries) != 55 or len(ids) != len(set(ids))):
        raise ValueError("V3.2 附件 1 必須有 55 項唯一檢查 ID")
    if ids != [f"NICS-WEB-A1-{x:03d}" for x in range(1, 56)]:
        raise ValueError("附件 1 檢查 ID 順序須與 PDF 一致")
    domains = {e["parent_section"] for e in entries}
    counts = {level: sum(level in e["applicable_levels"] for e in entries) for level in LEVELS}
    if len(domains) != 27 or counts != {"普": 33, "中": 44, "高": 55}:
        raise ValueError("附件 1 類別或適用等級數量不符")
    if data.get("category_count") != 27 or data.get("level_counts") != counts:
        raise ValueError("附件 1 清冊摘要不符")
    if data.get("scope", {}).get("excluded_implementation_technologies") != ["Java", "PHP"]:
        raise ValueError("附件 1 須延續 .NET 限定並排除 Java／PHP 專屬實作")
    valid_ids = {r["id"] for r in rules}
    if len(valid_ids) != len(rules):
        raise ValueError("原有檢核規則 ID 重複")
    for entry in entries:
        if (entry["verification_mode"] not in ("source", "hybrid", "external")
                or not entry["requirement"] or not entry["verification_focus"]
                or not (1 <= entry["pdf_page"] <= 5)
                or not entry["parent_section"].startswith("4.")
                or not entry["related_rule_ids"]
                or not set(entry["related_rule_ids"]).issubset(valid_ids)
                or not entry["applicable_levels"]
                or any(lev not in LEVELS for lev in entry["applicable_levels"])):
            raise ValueError(f"附件 1 查檢項目缺少必要資料：{entry['id']}")
    return data


def appendix_review_hints(rules: list[dict]) -> dict[str, list[dict]]:
    mapped: dict[str, list[dict]] = {rule["id"]: [] for rule in rules}
    for check in load_appendix1(rules)["checks"]:
        for rid in check["related_rule_ids"]:
            mapped[rid].append({
                "id": check["id"], "pdf_page": check["pdf_page"],
                "parent_section": check["parent_section"],
                "requirement": check["requirement"],
                "applicable_levels": check["applicable_levels"],
                "verification_mode": check["verification_mode"],
                "verification_focus": check["verification_focus"],
            })
    return mapped


def _normalize_review(review: dict | None) -> dict[str, dict]:
    if review is None:
        return {}
    if not isinstance(review, dict) or not isinstance(review.get("checks"), list):
        raise ValueError("web_appendix1_assessment.json 必須為包含 checks 陣列的物件")
    result = {}
    for entry in review["checks"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
            raise ValueError("附件 1 人工驗證必須有檢查 ID")
        rid = entry["id"]
        if rid in result:
            raise ValueError("附件 1 人工驗證重複：" + rid)
        if entry.get("status") not in VERIFIED_STATES:
            raise ValueError(f"{rid}: 人工驗證狀態須為 pass/fail/review/na")
        required = ("reason", "reviewer", "verified_on", "evidence")
        if not all(field in entry for field in required):
            raise ValueError(f"{rid}: 缺少人工驗證理由、審核者、日期或證據欄位")
        if any(not isinstance(entry[k], str) or not entry[k].strip()
               for k in ("reason", "reviewer")):
            raise ValueError(f"{rid}: 審核理由及審核者不得空白")
        try:
            date.fromisoformat(entry["verified_on"])
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{rid}: 日期不是有效的 YYYY-MM-DD") from exc
        evidence = entry["evidence"]
        if (not isinstance(evidence, list)
                or any(not isinstance(ref, str) or not ref.strip() for ref in evidence)):
            raise ValueError(f"{rid}: evidence 應為真實可追溯的參照字串陣列")
        if entry["status"] in ("pass", "fail") and not evidence:
            raise ValueError(f"{rid}: 符合或不符合都必須有實際核對的證據")
        result[rid] = {k: entry[k] for k in ("status", *required)}
    return result


def review_from_report(report: dict) -> dict:
    # 生成報告以後再次 render 時保留真實的人工審核紀錄。
    entries = []
    for entry in report.get("checks", []):
        if entry.get("status") in VERIFIED_STATES:
            entries.append({k: entry[k] for k in
                            ("id", "status", "reason", "reviewer", "verified_on", "evidence")})
    return {"checks": entries}


def build_appendix1(project: dict, rules: list[dict], review: dict | None = None) -> dict:
    level = project.get("protection_demand_level", "待確認")
    if level not in (*LEVELS, "待確認"):
        raise ValueError("防護需求分級須為普／中／高／待確認")
    basis = str(project.get("protection_demand_level_basis", "")).strip()
    if level in LEVELS and not basis:
        raise ValueError("系統正式分級需有保護需求分級依據，不能依機關責任 A～E 換算")
    verified = _normalize_review(review)
    catalog = load_appendix1(rules)
    known = {x["id"] for x in catalog["checks"]}
    if set(verified) - known:
        raise ValueError("附件 1 人工驗證存在未知 ID：" + ", ".join(sorted(set(verified) - known)))
    rows = []
    for item in catalog["checks"]:
        applicable = None if level == "待確認" else level in item["applicable_levels"]
        decision = verified.get(item["id"])
        if decision and applicable is not True:
            raise ValueError(f"{item['id']}: 未核實分級或該級不適用，不能填寫正式驗證結論")
        state = decision["status"] if decision else (
            "pending_level" if applicable is None else
            "not_assessed" if applicable else "not_applicable_by_level")
        row = {k: item[k] for k in
               ("id", "pdf_page", "parent_section", "category", "requirement",
                "applicable_levels", "verification_mode", "related_rule_ids",
                "verification_focus")}
        row.update({"applicable": applicable, "status": state})
        if decision:
            row.update(decision)
        rows.append(row)
    counts = dict(Counter(r["status"] for r in rows))
    return {
        "standard_id": catalog["standard_id"],
        "guide_version": "V3.2",
        "source_title": catalog["document_title"],
        "scope": catalog["scope"],
        "demand_level": level, "demand_level_basis": basis,
        "category_count": 27, "item_count": 55,
        "applicable_items": None if level == "待確認" else sum(r["applicable"] for r in rows),
        "status_counts": counts,
        "assessment_note": "附件是獨立查檢對照，不由 70 項 Pass 自動推定符合；人工證據參照仍須核實真實性。",
        "checks": rows,
    }


def validate_appendix1(project: dict, rules: list[dict], actual: dict) -> list[str]:
    try:
        rebuilt = build_appendix1(project, rules, review_from_report(actual))
        if rebuilt != actual:
            return ["web_guide_v32_appendix1 與原文清冊、適用級別或人工判定不一致"]
    except (ValueError, TypeError, KeyError, OSError) as exc:
        return [f"web_guide_v32_appendix1 無效：{exc}"]
    return []
