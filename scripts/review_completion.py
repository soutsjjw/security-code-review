#!/usr/bin/env python3
"""逐項執行狀態檢查，禁止把未執行工作偽裝成 review。"""
from collections import Counter

PLACEHOLDERS = ("尚未執行", "尚未審查", "尚未檢核", "尚未分析", "未進行審查", "格式範例")


def completion_errors(checks: list[dict], *, allow_demo: bool = False) -> list[str]:
    if allow_demo:
        return []
    errors = []
    repeated = Counter()
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
        if not isinstance(methods, list) or not methods or not all(isinstance(x, str) and x.strip() for x in methods):
            errors.append(f"{rid}: 缺少實際審查方法")
        if len(summary) < 15:
            errors.append(f"{rid}: 缺少具體檢核摘要（至少 15 字）")
        if any(x in summary or x in decision for x in PLACEHOLDERS):
            errors.append(f"{rid}: 仍含尚未審查之佔位文字")
        if check.get("status") == "review":
            if len(decision) < 15:
                errors.append(f"{rid}: review 須記錄已查核內容及無法確認原因")
            if not (execution.get("inspected_paths") or check.get("evidence")):
                errors.append(f"{rid}: review 缺少實際已讀來源檔或可核對證據；不得將尚未檢查當作待確認")
            if not any(word in decision + summary for word in (
                "待確認", "尚待", "仍待", "缺少", "缺乏", "待補", "無法", "不能確認",
                "未取得", "尚無", "不足", "待驗", "限制",
            )):
                errors.append(f"{rid}: review 未具體說明待補的外部／動態／政策證據")
            repeated[(decision, summary)] += 1
    for (decision, _), count in repeated.items():
        if count >= 5:
            errors.append(f"有 {count} 個 review 共用相同結論及執行摘要，須逐項查核：{decision[:50]}")
    return errors
