"""WEB 應用程式安全參考指引 V3.2：僅保留 ASP.NET/.NET 與跨技術通用查核。

本模組提供技術指引/映射；不會修改原 70 項進度，也不會把相關規則 Pass
認定成整個指引控制措施通過。
"""
from __future__ import annotations
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "standards" / "nics-web-guide-v3.2.yaml"
EXPECTED_DOMAINS = {"4.1": 3, "4.2": 6, "4.3": 2, "4.4": 5, "4.5": 8, "4.6": 2, "4.7": 3}


def load_web_guide(rules: list[dict]) -> dict:
    doc = yaml.safe_load(CATALOG.read_text(encoding="utf-8"))
    items = doc.get("controls", [])
    topics = [topic for item in items for topic in item.get("implementation_topics", [])]
    if doc.get("standard_id") != "NICS-WEB-GUIDE" or doc.get("version") != "V3.2":
        raise ValueError("Web 指引必須使用 V3.2 版本化清冊")
    if len(items) != 29 or len(topics) != 35:
        raise ValueError("Web 指引第 4 章應有 29 類措施、35 個細部技術條次")
    if len({c["id"] for c in items}) != len(items) or len({t["id"] for t in topics}) != len(topics):
        raise ValueError("Web 指引的控制條次 ID 不得重複")
    if sorted(doc["scope"]["excluded_implementation_technologies"]) != ["Java", "PHP"]:
        raise ValueError("Web 指引僅允許 ASP.NET/.NET 與通用控制，不納入 Java/PHP 技術範例")
    counts = {p: sum(c["source_section"].startswith(p + ".") for c in items) for p in EXPECTED_DOMAINS}
    if counts != EXPECTED_DOMAINS:
        raise ValueError("Web 指引 7 大構面/29 類控制措施數量錯誤")
    valid_ids = {r["id"] for r in rules}
    if len(valid_ids) != len(rules):
        raise ValueError("原有安全規則 ID 重複")
    for row in items:
        if (row.get("id") != "NICS-WEB-" + row.get("source_section", "")
                or row.get("mapping_type") != "related_guidance_not_full_equivalence"
                or row.get("verification_mode") not in ("source", "hybrid", "external")
                or not isinstance(row.get("pdf_page"), int)
                or not row.get("review_focus")
                or not set(row.get("related_rule_ids", [])).issubset(valid_ids)):
            raise ValueError("V3.2 控制對照或查核方向不完整：" + str(row.get("id")))
        for topic in row["implementation_topics"]:
            if (topic.get("id") != "NICS-WEB-" + topic.get("source_section", "")
                    or not topic["source_section"].startswith(row["source_section"] + ".")
                    or topic.get("verification_mode") not in ("source", "hybrid", "external")
                    or not topic.get("review_focus")
                    or not set(topic.get("related_rule_ids", [])).issubset(valid_ids)
                    or not isinstance(topic.get("pdf_page"), int)
                    or not topic.get("levels_evidence")
                    or not isinstance(topic.get("observed_levels"), list)
                    or not topic["observed_levels"]
                    or any(level not in ("普", "中", "高") for level in topic["observed_levels"])):
                raise ValueError("V3.2 細部條次無效：" + str(topic.get("id")))
    return doc


def web_guide_review_hints(rules: list[dict]) -> dict[str, list[dict]]:
    """僅列查核提示，不傳遞 Java/PHP 範例或給出 Pass/Fall 結論。"""
    doc = load_web_guide(rules)
    mapped: dict[str, list[dict]] = {rule["id"]: [] for rule in rules}
    for cat in doc["controls"]:
        for rid in cat["related_rule_ids"]:
            related_topics = [t for t in cat["implementation_topics"] if rid in t["related_rule_ids"]]
            mapped[rid].append({
                "id": cat["id"], "section": cat["source_section"], "title": cat["title"],
                "pdf_page": cat["pdf_page"],
                "verification_mode": cat["verification_mode"],
                "review_focus": cat["review_focus"],
                "implementation_topics": [{
                    "id": t["id"], "section": t["source_section"], "pdf_page": t["pdf_page"],
                    "title": t["title"], "verification_mode": t["verification_mode"],
                    "review_focus": t["review_focus"],
                    "observed_levels": t["observed_levels"],
                    "levels_evidence": t["levels_evidence"],
                } for t in related_topics],
                "mapping_type": cat["mapping_type"],
                "tech_scope": "ASP.NET/.NET 與通用 Web 控制（不含 Java/PHP 範例）",
            })
    return mapped


def build_web_guide_index(rules: list[dict]) -> dict:
    """報告中的指引對照索引；絕不以 70 項狀態推導整類符合與否。"""
    doc = load_web_guide(rules)
    return {
        "standard_id": doc["standard_id"],
        "version": doc["version"],
        "revision_date": doc["revision_date"],
        "scope": doc["scope"],
        "owasp_reference_in_document": doc["owasp_reference_in_document"],
        "attachment_status": doc["attachment_status"],
        "category_count": 29,
        "implementation_topic_count": 35,
        "assessment_note": "此為技術檢查指引與原有 70 項的一對多交叉索引；無獨立符合性判定或新進度數量。",
        "controls": [{
            "id": c["id"], "section": c["source_section"], "title": c["title"],
            "pdf_page": c["pdf_page"],
            "verification_mode": c["verification_mode"],
            "related_rule_ids": c["related_rule_ids"],
            "review_focus": c["review_focus"],
            "implementation_topics": [{
                "id": t["id"], "section": t["source_section"], "pdf_page": t["pdf_page"],
                "title": t["title"], "verification_mode": t["verification_mode"],
                "review_focus": t["review_focus"],
                "observed_levels": t["observed_levels"],
                "levels_evidence": t["levels_evidence"],
            } for t in c["implementation_topics"]],
        } for c in doc["controls"]],
    }


def validate_web_guide_index(rules: list[dict], actual: dict) -> list[str]:
    try:
        if build_web_guide_index(rules) != actual:
            return ["web_guide_v32 與指引版本、範圍或檢核條次不一致"]
    except (ValueError, TypeError, KeyError, OSError) as exc:
        return [f"web_guide_v32 無法驗證：{exc}"]
    return []
