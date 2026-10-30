"""報告摘要自動補充：執行工具、個資線索、待確認事項與靜態風險初判。"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Mapping

from source_reader import DEFAULT_LEGACY_ENCODINGS, read_source_text
from assessment_consistency import (
    clip_text, impact_type_label, review_breakdown, review_ratio, REVIEW_RATIO_WARN,
)

# 只使用明確指向個人的欄位線索，不以搜尋不到欄位宣稱「未處理個資」。
PERSONAL_FIELD = re.compile(
    r"(?i)(?:身分證(?:字號|號碼)?|身份證(?:字號|號碼)?|護照(?:號碼|號)?|出生日期|"
    r"national[_-]?id|identity[_-]?(?:card|number)|passport[_-]?(?:no|number)|"
    r"date[_-]?of[_-]?birth|birth[_-]?date|personal[_-]?id|"
    r"email[_-]?address|mobile[_-]?(?:phone|number))"
)
SOURCE_SUFFIXES = {".cs", ".cshtml", ".ts", ".tsx", ".js", ".jsx", ".py", ".go",
                   ".rb", ".sql", ".json", ".yaml", ".yml", ".xml", ".config"}
EXCLUDED_PARTS = {"test", "tests", "__tests__", "fixtures", "samples", "examples",
                  "node_modules", "vendor", "bin", "obj"}
RISK_ORDER = {"info": 0, "low": 1, "medium": 2, "med": 2, "high": 3, "critical": 4}
RISK_LEVEL = {"info": "資訊", "low": "低", "medium": "中", "high": "高", "critical": "重大"}


def _inspected_paths(assessment: dict[str, Any]) -> list[str]:
    return sorted({
        str(path).replace("\\", "/")
        for check in assessment.get("checks", [])
        if (check.get("execution") or {}).get("state") == "completed"
        for path in (check.get("execution") or {}).get("inspected_paths", [])
        if isinstance(path, str)
    })


def infer_personal_data(
    assessment: dict[str, Any], source_root: Path | None,
    source_encodings: tuple[str, ...] = DEFAULT_LEGACY_ENCODINGS,
) -> dict[str, Any]:
    """從已審查的真實來源檔找保守線索；沒有線索不代表沒有個資。"""
    evidence: list[dict[str, Any]] = []
    if source_root is not None:
        root = source_root.resolve()
        for name in _inspected_paths(assessment):
            relative = Path(name)
            if (relative.is_absolute() or ".." in relative.parts
                    or any(part.lower() in EXCLUDED_PARTS for part in relative.parts)
                    or relative.suffix.lower() not in SOURCE_SUFFIXES):
                continue
            absolute = (root / relative).resolve()
            if not absolute.is_relative_to(root) or not absolute.is_file():
                continue
            try:
                if absolute.stat().st_size > 1_000_000:
                    continue
                source = read_source_text(absolute, source_encodings)[0]
            except (OSError, UnicodeError, LookupError):
                continue
            for number, line in enumerate(source.splitlines(), 1):
                if line.lstrip().startswith(("//", "#", "*", "<!--")):
                    continue
                if PERSONAL_FIELD.search(line):
                    evidence.append({"path": name, "line_start": number, "line_end": number})
                    break
            if len(evidence) >= 3:
                break
    if evidence:
        return {
            "status": "是",
            "basis": "已審查原始碼發現明確個人識別欄位線索；屬靜態初判，尚需核對實際資料流及環境。",
            "evidence": evidence,
        }
    return {
        "status": "待確認",
        "basis": "已審查檔案未取得足以確認個資處理的明確線索；靜態分析無法證明系統不處理個資。",
        "evidence": [],
    }


def resolve_personal_data(
    project: dict[str, Any], assessment: dict[str, Any],
    source_root: Path | None, encodings: tuple[str, ...],
) -> None:
    supplied = project.get("personal_data")
    if supplied in ("是", "否"):
        project["personal_data_assessment"] = {
            "status": supplied,
            "basis": "受測專案 project.json 已提供此聲明；非由報告產生器證明，應核對其業務及資料流依據。",
            "evidence": [],
        }
        return
    inferred = infer_personal_data(assessment, source_root, encodings)
    project["personal_data"] = inferred["status"]
    project["personal_data_assessment"] = inferred


def detect_reviewer(
    existing: str | None, env: Mapping[str, str] | None = None,
) -> str:
    """可信來源只有 Agent 明確寫入的介面名稱或明確環境標識。"""
    vars = os.environ if env is None else env
    names = {"Codex App", "Codex CLI", "Claude Code"}
    if existing in names:
        return existing
    explicit = vars.get("SECURITY_CODE_REVIEW_EXECUTOR", "").strip()
    if explicit in names:
        return explicit
    if vars.get("CLAUDECODE"):
        return "Claude Code"
    if vars.get("CODEX_THREAD_ID"):
        return "Codex（執行介面無法辨識）"
    if existing and existing.startswith("Codex"):
        return "Codex（執行介面無法辨識）"
    return "AI 審查工具（執行介面無法辨識）"


def build_overall_risk(assessment: dict[str, Any]) -> dict[str, str]:
    """依已記錄 Finding 的嚴重度、影響與信心初判，不因未發現弱點判低風險。"""
    findings = [item for item in assessment.get("findings", [])
                if item.get("severity") in RISK_ORDER]
    if not findings:
        return {
            "level": "review",
            "summary": "本次未記錄可據以判定整體等級的已確認弱點；靜態審查未發現不代表低風險。"
                       "仍需確認系統暴露情況、業務影響、部署防護與動態測試。",
        }
    most = max(findings, key=lambda f: RISK_ORDER[f["severity"]])
    level = "medium" if most["severity"] == "med" else most["severity"]
    confidence = most.get("confidence", "未記錄")
    impact = clip_text(most.get("impact") or "影響範圍尚待核實", 120)
    type_label = impact_type_label(most)
    if type_label:
        impact = f"{impact}（影響面向：{type_label}）"
    still_review = sum(c.get("status") == "review" for c in assessment.get("checks", []))
    supplement = f"；另有 {still_review} 項規則需補證據" if still_review else ""
    counts = {s: sum(f.get("severity") == s for f in findings) for s in RISK_ORDER}
    breakdown = "、".join(f"{RISK_LEVEL['medium' if s == 'med' else s]} {n} 筆" for s, n in counts.items() if n)
    if len(findings) > 1 and breakdown:
        supplement = f"；共 {len(findings)} 筆已記錄弱點（{breakdown}）" + supplement
    return {
        "level": level,
        "summary": (
            f"靜態初判為{RISK_LEVEL[level]}風險；以已記錄弱點中最高嚴重度"
            f" {most.get('id', '未編號')} 為主要依據，已記錄影響：{impact}；"
            f"證據信心：{confidence}{supplement}。"
            "仍需核實實際可利用性、外部暴露、業務衝擊及補償控制；"
            "此為初步風險排序，不是正式風險接受或滲透測試結論。"
        ),
    }


def build_pending_information(
    project: dict[str, Any], assessment: dict[str, Any],
    limitations: list[str] | None = None,
    review_ratio_note: str | None = None,
) -> list[str]:
    pending: list[str] = []
    if project.get("security_level") not in ("A", "B", "C", "D", "E", "不適用"):
        preliminary = project.get("security_level_assessment") or {}
        pending.extend(preliminary.get("missing_information") or ["機關正式責任等級及核定依據"])
    if project.get("protection_demand_level") not in ("普", "中", "高"):
        pending.append("資通系統防護需求分級（普／中／高）及其可核對依據")
    if project.get("personal_data") == "待確認":
        pending.append("實際個資處理範圍、資料流與儲存情況")
    review_ids = [c["id"] for c in assessment.get("checks", []) if c.get("status") == "review"]
    if review_ids:
        listed = "、".join(review_ids[:8])
        kinds = review_breakdown(assessment.get("checks", []))
        if kinds["static"] or kinds["external"] or kinds["delegated"]:
            pending.append(
                f"{len(review_ids)} 項 review：靜態查核已完成、僅缺部署／政策／動態佐證 {kinds['static']} 項；"
                f"本質上需外部或制度證據 {kinds['external']} 項；"
                f"已確認外部責任但缺運作證據 {kinds['delegated']} 項；"
                f"未分類 {kinds['unclassified']} 項（例如 {listed}）")
        else:
            pending.append(f"{len(review_ids)} 項檢核尚缺部署／政策／動態佐證（例如 {listed}）")
    review, total = review_ratio(assessment)
    if total and review / total > REVIEW_RATIO_WARN:
        note = (review_ratio_note or "").strip() or "尚未說明比例偏高的原因"
        pending.append(f"review 占 {review}/{total}，超過 {int(REVIEW_RATIO_WARN * 100)}% 警示門檻：{note}")
    for item in limitations or []:
        if isinstance(item, str) and item.strip():
            pending.append(item.strip())
    return list(dict.fromkeys(pending))
