#!/usr/bin/env python3
"""Read-only, rule-scoped first-pass blocker diagnosis.

Never modifies assessment, Findings, manifests, source or baseline.
A stable signature allows the agent to recognize identical failed retries.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

RULE_ID = re.compile(r"\b(?:AC|AU|IN|CR|EH|LG|DP|PD|BC|SI)-\d{2}\b")
ASSESSMENT = Path("reports/security-code-review/assessment.json")
FIXES: dict[str, str] = {
    "unrelated_evidence": "重新核對此規則的控制責任和實際來源；無關證據只能經合法修訂流程取代",
    "weak_source_evidence": "重新取得真正能證明規則結論的執行邏輯、版本／漏洞掃描或外部工件，不能重用套件宣告",
    "delegation_unverified": "先取得可追溯的外部控制責任歸屬；缺少 Workflow 不等於已委外",
    "missing_external_decision": "確認真正影響結論的外部工件、負責單位及兩種不同判定結果",
    "incomplete_static": "完成來源、呼叫鏈與組態的調查，不能用 review 當作尚未檢查完",
    "integrity": "核對來源快照、檔案覆蓋、關聯、Journal 與既有 Findings，禁止覆寫或略過守門",
    "other": "依權威錯誤訊息定向補查；同一證據沒有改變時不要重試相同驗證",
}


def classify(message: str) -> str:
    if any(x in message for x in ("無關", "不相關", "關聯規則", "未連結正式", "證據不一致")):
        return "unrelated_evidence"
    if any(x in message for x in ("只有宣告", "僅為宣告", "無效行號", "不能證明控制", "來源證據只含宣告", "控制實際執行位置", "來源僅有")):
        return "weak_source_evidence"
    if any(x in message for x in ("P0", "委外", "責任歸屬")):
        return "delegation_unverified"
    if any(x in message for x in ("P3", "Q1", "外部工件", "decision_outcomes", "缺口")):
        return "missing_external_decision"
    if any(x in message for x in ("未完成的程式碼", "查核尚未", "尚未追查", "未完成來源", "open_static_questions")):
        return "incomplete_static"
    if any(x in message for x in ("快照", "來源異動", "Journal", "Manifest", "逐檔覆蓋", "完整性")):
        return "integrity"
    return "other"


def summarize(messages: list[str]) -> dict[str, Any]:
    """Deterministic diagnostic summary; no automatic verdicts or repairs."""
    unique = sorted(set(messages))
    signature = hashlib.sha256(
        json.dumps(unique, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    blockers = []
    ids: set[str] = set()
    for message in unique:
        rules = sorted(set(RULE_ID.findall(message)))
        ids.update(rules)
        category = classify(message)
        blockers.append({
            "rule_ids": rules,
            "category": category,
            "message": message,
            "required_action": FIXES[category],
        })
    return {
        "ready_for_second_pass": not blockers,
        "blocked_count": len(blockers),
        "blocker_signature": signature,
        "recheck_rule_ids": sorted(ids),
        "blockers": blockers,
        "retry_policy": (
            "可啟動第二輪" if not blockers else
            "只補查列出的規則及必要來源；如 blocker_signature 不變，禁止重複執行相同驗證，"
            "須查明證據缺口或取得真正外部資料。不可假造資料、改判 Pass、清除 Findings 或繞過守門。"
        ),
    }


def diagnose(target: Path, assessment: dict[str, Any]) -> dict[str, Any]:
    from adversarial_recheck import first_pass_issues
    return summarize(first_pass_issues(target.resolve(), assessment))


def main() -> int:
    parser = argparse.ArgumentParser(description="唯讀列出進入第二輪前的所有證據阻斷")
    parser.add_argument("--target", type=Path, default=Path.cwd())
    args = parser.parse_args()
    target = args.target.resolve()
    assessment_file = target / ASSESSMENT
    try:
        assessment = json.loads(assessment_file.read_text(encoding="utf-8"))
        result = diagnose(target, assessment)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"ready_for_second_pass": False, "error": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0  # Diagnostic query succeeded; readiness is explicitly in JSON.


if __name__ == "__main__":
    raise SystemExit(main())
