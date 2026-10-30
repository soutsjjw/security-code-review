"""NICS WEB V3.2 附件3：六項 HTTP 安全標頭輔助檢測與證據記錄。

保留既有 CR-05 的規則身份與 70/70 進度。未取得現場回應及確實人工確認時
不能宣稱六個標頭已實際驗證；報告預設全數 not_assessed。
"""
from __future__ import annotations

from collections import Counter
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "standards" / "nics-web-v3.2-appendix3.yaml"
HEADERS = (
    "Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options",
    "X-Frame-Options", "Referrer-Policy", "Permissions-Policy",
)
STATES = ("pass", "fail", "review", "na")


def load_headers(rules: list[dict]) -> dict:
    doc = yaml.safe_load(CATALOG.read_text(encoding="utf-8"))
    checks = doc["checks"]
    expected_ids = [
        "NICS-WEB-A3-CSP", "NICS-WEB-A3-HSTS", "NICS-WEB-A3-NOSNIFF",
        "NICS-WEB-A3-FRAME", "NICS-WEB-A3-REFERRER", "NICS-WEB-A3-PERMISSIONS",
    ]
    if (doc.get("standard_id") != "NICS-WEB-GUIDE-APPENDIX3"
            or doc.get("version") != "V3.2"
            or doc.get("source_pages") != 10
            or [x["id"] for x in checks] != expected_ids
            or tuple(x["header"] for x in checks) != HEADERS):
        raise ValueError("V3.2 附件3 必須有六項指定的 HTTP 安全標頭")
    if doc.get("scope", {}).get("excluded_implementation_technologies") != ["Java", "PHP"]:
        raise ValueError("V3.2 附件3 必須排除 Java/PHP 專屬實作")
    valid_ids = {r["id"] for r in rules}
    if len(valid_ids) != len(rules):
        raise ValueError("原 70 項規則 ID 不得重複")
    for item in checks:
        if (item["verification_mode"] != "source_plus_http_response"
                or "CR-05" not in item["related_rule_ids"]
                or not set(item["related_rule_ids"]).issubset(valid_ids)
                or not item["source_pdf_pages"]
                or any(not isinstance(p, int) or not 1 <= p <= 10
                       for p in item["source_pdf_pages"])
                or not item["review_steps"] or not item["source_recommendation"]
                or not item["implementation_cautions"]):
            raise ValueError("V3.2 附件3 內容不完整：" + item["id"])
    return doc


def header_review_hints(rules: list[dict]) -> dict[str, list[dict]]:
    """純粹供 Agent 真正檢查 ASP.NET/IIS/HTTP 回應，不自動記錄合規結果。"""
    mapped = {r["id"]: [] for r in rules}
    for item in load_headers(rules)["checks"]:
        for rid in item["related_rule_ids"]:
            mapped[rid].append({
                "id": item["id"], "header": item["header"],
                "source_pdf_pages": item["source_pdf_pages"],
                "review_steps": item["review_steps"],
                "implementation_cautions": item["implementation_cautions"],
                "evidence_needed": "設定檔或 Middleware 位置 + 已核實的 HTTPS HTTP 回應（URL/環境/日期），無實測時只能部分評估",
            })
    return mapped


def _validate_review(review: dict | None) -> dict[str, dict]:
    if review is None:
        return {}
    if not isinstance(review, dict) or not isinstance(review.get("checks"), list):
        raise ValueError("web_appendix3_assessment.json 需要 checks 陣列")
    mapped = {}
    for row in review["checks"]:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            raise ValueError("附件3 的每項查證必須包含 id")
        rid = row["id"]
        if rid in mapped:
            raise ValueError("附件3 存在重複 ID：" + rid)
        if row.get("status") not in STATES:
            raise ValueError(f"{rid}: 僅允許 pass/fail/review/na")
        if any(not isinstance(row.get(k), str) or not row[k].strip()
               for k in ("reason", "reviewer", "verified_on")):
            raise ValueError(f"{rid}: 必須記錄理由、審核者及有效日期")
        try:
            date.fromisoformat(row["verified_on"])
        except (ValueError, TypeError) as exc:
            raise ValueError(f"{rid}: verified_on 日期無效") from exc
        evidence = row.get("evidence", [])
        response = row.get("http_response_evidence", [])
        if any(not isinstance(a, list) or any(not isinstance(x, str) or not x.strip() for x in a)
               for a in (evidence, response)):
            raise ValueError(f"{rid}: evidence 與 http_response_evidence 必須為非空字串組成的陣列")
        if row["status"] in ("pass", "fail") and not evidence and not response:
            raise ValueError(f"{rid}: pass/fail 需具體可追溯證據")
        if row["status"] == "pass":
            if not response:
                raise ValueError(f"{rid}: 不可只憑原始碼或 IIS 設定判定標頭已生效；需 HTTP 實際回應證據")
            if not isinstance(row.get("environment"), str) or not row["environment"].strip():
                raise ValueError(f"{rid}: pass 必須指明經核實的部署環境")
        observed = row.get("observed_value", "")
        if not isinstance(observed, str):
            raise ValueError(f"{rid}: observed_value 必須為文字（敏感內容應遮蔽）")
        mapped[rid] = {
            "status": row["status"], "reason": row["reason"],
            "reviewer": row["reviewer"], "verified_on": row["verified_on"],
            "environment": row.get("environment", ""),
            "observed_value": observed,
            "evidence": evidence,
            "http_response_evidence": response,
        }
    return mapped


def review_from_report(report: dict) -> dict:
    """讓 --report 重建報告時保留原始實際審核資料。"""
    return {"checks": [
        {"id": item["id"], **{k: item[k] for k in (
            "status", "reason", "reviewer", "verified_on", "environment",
            "observed_value", "evidence", "http_response_evidence"
        )}}
        for item in report.get("checks", []) if item.get("status") in STATES
    ]}


def build_appendix3(rules: list[dict], review: dict | None = None) -> dict:
    source = load_headers(rules)
    verified = _validate_review(review)
    catalog = source["checks"]
    if set(verified) - {item["id"] for item in catalog}:
        raise ValueError("附件3 審核包含不明標頭 ID")
    result = []
    for item in catalog:
        row = {key: item[key] for key in (
            "id", "header", "source_pdf_pages", "related_rule_ids",
            "verification_mode", "purpose", "source_recommendation",
            "review_steps", "implementation_cautions"
        )}
        row["status"] = "not_assessed"
        row["observed_value"] = ""
        row["environment"] = ""
        row["evidence"] = []
        row["http_response_evidence"] = []
        if item["id"] in verified:
            row.update(verified[item["id"]])
        result.append(row)
    return {
        "standard_id": source["standard_id"],
        "version": source["version"],
        "source_document": source["source_document"],
        "source_pages": source["source_pages"],
        "related_main_guide_control": source["related_main_guide_control"],
        "scope": source["scope"],
        "level_note": source["level_note"],
        "header_count": 6,
        "status_counts": dict(Counter(x["status"] for x in result)),
        "assessment_note": "本章僅補強 CR-05 的六個技術子項；未核實 HTTPS 回應不會自動 Pass。實際證據參照須由審核者確認真實性。",
        "checks": result,
    }


def validate_appendix3(rules: list[dict], actual: dict) -> list[str]:
    try:
        rebuilt = build_appendix3(rules, review_from_report(actual))
        if actual != rebuilt:
            return ["web_guide_v32_appendix3 與來源清冊／HTTP 觀測證據不一致"]
    except (KeyError, ValueError, TypeError, OSError) as exc:
        return [f"web_guide_v32_appendix3 無效：{exc}"]
    return []
