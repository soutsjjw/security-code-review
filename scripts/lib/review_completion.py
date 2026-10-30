#!/usr/bin/env python3
"""核心規則完成證據檢查：拒絕未實際查核、制式 review 與缺乏定位資訊的證據。

這是保守的機械檢查；無法代替人工確認資料流、控制有效性或證據真實性。
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict

PLACEHOLDERS = ("尚未執行", "尚未審查", "尚未檢核", "尚未分析", "未進行審查", "格式範例")
# 泛稱所有外部資料皆缺少不等於明確指出「本規則」的證據缺口。
GENERIC_REVIEW_GAPS = (
    "部署設定、正式政策、運作紀錄或動態測試",
    "部署、政策或動態測試",
    "部署／政策／動態測試",
    "保留原判定與外部證據限制",
    "缺乏外部證據限制",
    "仍待確認的外部證據",
    "後續需部署、政策",
    "部署、政策與動態測試",
    "保留既有 review 結論",
)

PENDING_WORDS = ("待確認", "尚待", "仍待", "缺少", "缺乏", "待補", "無法", "不能確認",
                 "未取得", "尚無", "不足", "待驗", "限制")
# 尚未取得外部資料並非已完成靜態查核的替代證據。
LOCATABLE_KINDS = frozenset({
    "source", "configuration", "test", "scan", "deployment", "operating_record",
    "policy", "interview", "other",
})
RULE_PATTERN = re.compile(r"\b(?:AC|AU|IN|CR|EH|LG|DP|PD|BC|SI)-\d{2}\b", re.IGNORECASE)
PATH_PATTERN = re.compile(r"(?<![\w])(?:[\w.+-]+[/\\])+[\w.+-]+")
NUMBER_PATTERN = re.compile(r"\d+")


def template_signature(text: str) -> str:
    """找出只更換規則 ID、檔案路徑、行號／數值的重複說明。"""
    result = RULE_PATTERN.sub("<RULE>", text)
    result = PATH_PATTERN.sub("<PATH>", result)
    result = NUMBER_PATTERN.sub("#", result)
    return " ".join(result.split()).casefold()


def _located_evidence(evidence: list[dict]) -> bool:
    """至少一筆有可追查定位的證據；任意敘述或單純檔案列表不足以交付。"""
    for ev in evidence:
        if not isinstance(ev, dict) or ev.get("kind") not in LOCATABLE_KINDS:
            continue
        path = ev.get("path")
        if ev["kind"] == "source":
            if (isinstance(path, str) and path.strip() and
                isinstance(ev.get("line_start"), int) and ev["line_start"] > 0 and
                isinstance(ev.get("line_end"), int) and ev["line_end"] >= ev["line_start"]):
                return True
        elif (isinstance(path, str) and path.strip()) or (
            isinstance(ev.get("artifact_id"), str) and ev["artifact_id"].strip()
        ):
            return True
    return False


def completion_errors(checks: list[dict], *, allow_demo: bool = False) -> list[str]:
    """正式報告前必須對已完成規則提供證據定位、個別判定與缺口。

    'completed' 不代表 pass；缺部署／政策證據的 review 仍可完成，
    但必須指出已檢查的內容和真正缺少的資料。
    """
    if allow_demo:
        return []
    errors: list[str] = []
    repeated = Counter()
    signatures: dict[tuple[str, str], set[str]] = defaultdict(set)
    for check in checks:
        rid = check.get("id", "?")
        execution = check.get("execution") or {}
        state = execution.get("state")
        if state != "completed":
            errors.append(f"{rid}: 尚未完成實際檢核（execution.state={state!r}）")
            continue
        methods = execution.get("methods", [])
        summary = str(execution.get("summary", "")).strip()
        decision = str(check.get("decision_reason", "")).strip()
        status = check.get("status")
        evidence = check.get("evidence") or []
        if not isinstance(methods, list) or not methods or not all(isinstance(x, str) and x.strip() for x in methods):
            errors.append(f"{rid}: 缺少實際審查方法")
        if len(summary) < 15:
            errors.append(f"{rid}: 缺少具體檢核摘要（至少 15 字）")
        if any(x in summary or x in decision for x in PLACEHOLDERS):
            errors.append(f"{rid}: 仍含尚未審查之佔位文字")
        if status in ("review", "pass", "fail"):
            if not _located_evidence(evidence):
                errors.append(
                    f"{rid}: {status} 缺少具體可追溯的檢核證據"
                    "（來源路徑與行號，或設定／測試／外部工件定位）；"
                    "僅有 inspected_paths／固定敘述不得宣稱 completed"
                )
        if status == "review":
            if len(decision) < 15:
                errors.append(f"{rid}: review 須記錄已查核內容及無法確認原因")
            if not any(word in decision + summary for word in PENDING_WORDS):
                errors.append(f"{rid}: review 未具體說明待補的外部／動態／政策證據")
            if any(gap in decision for gap in GENERIC_REVIEW_GAPS):
                errors.append(f"{rid}: review 使用制式外部證據清單；須明確指出本規則需要何種工件／環境及已確認的靜態範圍")
            # review 可以是真正完成靜態部分後缺外部證據，不能只保留先前狀態。
            if any(term in decision for term in
                   ("保留原判定", "延續原審查結論", "依舊判定", "保留既有", "沿用原有")):
                errors.append(f"{rid}: review 沿用舊判定但未重新核對實際控制與缺少工件")
            repeated[(decision, summary)] += 1
        if status in ("pass", "fail", "review"):
            signatures[("執行摘要", template_signature(summary))].add(str(rid))
            signatures[("判定理由", template_signature(decision))].add(str(rid))
            for ev in evidence:
                if isinstance(ev, dict) and isinstance(ev.get("description"), str):
                    signatures[("證據描述", template_signature(ev["description"]))].add(str(rid))
    for (decision, _), count in repeated.items():
        if count >= 5:
            errors.append(f"有 {count} 個 review 共用相同結論及執行摘要，須逐項查核：{decision[:50]}")
    # 僅作高度重複模板攔截，不要求某個固定 pass/fail/review 比率。
    limit = max(5, (len(checks) + 5) // 6)
    for (kind, template), ids in signatures.items():
        if len(ids) >= limit and len(template) >= 12:
            errors.append(
                f"{len(ids)} 個 completed 檢核共用制式{kind}（僅變換 ID／路徑／數字）："
                + "、".join(sorted(ids)[:8])
            )
    return errors
