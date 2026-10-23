#!/usr/bin/env python3
"""P3 待確認裁決守門：只核對人工證據的可追溯性，不自動改判 pass/fail/review。"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from control_effectiveness import snapshot_fingerprint
from review_decision import load_decision_matrix, _is_weak_source_evidence

RELATIVE = Path("reports/security-code-review/analysis")
INDEX = RELATIVE / "structure-index.json"
SNAPSHOT = RELATIVE / "review-snapshot.json"
AUDITS = RELATIVE / "decision-audits.json"
CONTRACT_VERSION = 1

CATEGORIES = frozenset({
    "deployment", "operational_record", "organization_policy", "platform_configuration",
    "external_scan",
})
TEST_ONLY = ("動態測試", "邊界測試", "測試結果", "測試案例", "缺少測試", "缺乏測試")


def guidance(rule_id: str) -> dict[str, Any]:
    matrix = load_decision_matrix()
    if rule_id not in matrix:
        raise ValueError(f"未知規則：{rule_id}")
    rule = matrix[rule_id]
    return {
        "mode": rule["mode"],
        "manual_boundary": rule["manual_boundary"],
        "pass_condition": rule["pass_condition"],
        "review_allowed_only_when": "已完成靜態查核，且明確的儲存庫外條件確實影響結論",
        "review_kind": ("external_only 或 static_done_external_pending"
                        if rule["mode"] == "external" else "static_done_external_pending"),
        "external_categories": sorted(CATEGORIES),
        "required_audit_fields": [
            "status", "review_kind", "git_revision", "snapshot_fingerprint",
            "static_result", "static_conclusion", "searched_paths", "static_evidence",
            "external_gap", "open_static_questions",
        ],
        "prohibited_review_reason": "僅缺非必要動態測試、未完成來源追查、已由程式碼證實的弱點",
        "note": "審查紀錄不構成自動合格判定；靜態弱點須 fail + Finding",
    }


def _read_json(path: Path, default: Any) -> Any:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else default


def adjudication_errors(target: Path, checks: list[dict]) -> list[str]:
    """只有 P3 新索引啟用；P2 舊索引不會因工具升級而悄悄重解判定。"""
    index = _read_json(target / INDEX, {})
    if not isinstance(index, dict) or index.get("decision_adjudication_version") != CONTRACT_VERSION:
        return []
    snapshot = _read_json(target / SNAPSHOT, {})
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("source_hashes"), dict):
        return ["P3: 缺少審查來源快照"]
    audits = _read_json(target / AUDITS, {})
    if not isinstance(audits, dict):
        return ["P3: decision-audits.json 應為規則 ID 對應的物件"]
    matrix = load_decision_matrix()
    known_paths = snapshot["source_hashes"]
    full_hash = snapshot_fingerprint(snapshot)
    issues: list[str] = []
    for check in checks:
        rid = check.get("id")
        if rid not in matrix or (check.get("execution") or {}).get("state") != "completed":
            continue
        if check.get("status") != "review":
            continue
        record = audits.get(rid)
        if not isinstance(record, dict):
            issues.append(f"{rid}: P3 尚未說明真正阻斷結論的外部證據，不能完成 review")
            continue
        kind = check.get("review_kind")
        if kind not in {"static_done_external_pending", "external_only"}:
            issues.append(f"{rid}: review_kind 須明確分類")
        if matrix[rid]["mode"] != "external" and kind != "static_done_external_pending":
            issues.append(f"{rid}: 靜態／混合規則不可跳過程式碼查核改成 external_only")
        if record.get("status") != "review" or record.get("review_kind") != kind:
            issues.append(f"{rid}: P3 判定紀錄的狀態及分類與正式檢核衝突")
        if record.get("git_revision") != snapshot.get("git_revision") or (
                record.get("snapshot_fingerprint") != full_hash):
            issues.append(f"{rid}: P3 判定紀錄的來源版本已失效，須重新查核")
        static_result = record.get("static_result")
        expected = ("external_control" if kind == "external_only" else "control_satisfied")
        if static_result != expected:
            issues.append(f"{rid}: P3 靜態分析未完成或已發現缺陷，不得以 review 迴避 fail／pending")
        conclusion = record.get("static_conclusion")
        if not isinstance(conclusion, str) or len(conclusion.strip()) < 24:
            issues.append(f"{rid}: P3 須具體記錄已查證的靜態結果與責任範圍")
        open_questions = record.get("open_static_questions")
        if not isinstance(open_questions, list) or open_questions:
            issues.append(f"{rid}: P3 尚有未完成的程式碼／組態查核，不得完成 review")
        searched = record.get("searched_paths")
        inspected = (check.get("execution") or {}).get("inspected_paths") or []
        inspected_paths = set(inspected) if isinstance(inspected, list) else set()
        if not isinstance(searched, list) or any(not isinstance(p, str) or p not in known_paths
                                                or p not in inspected_paths for p in searched):
            issues.append(f"{rid}: P3 搜尋的來源路徑不在快照或正式 inspected_paths")
            searched = []
        if kind == "static_done_external_pending" and not searched:
            issues.append(f"{rid}: P3 靜態部分沒有具體 inspected_paths，不能宣稱完成")
        evidence = record.get("static_evidence")
        if not isinstance(evidence, list):
            issues.append(f"{rid}: P3 static_evidence 必須是來源行號清單")
            evidence = []
        if kind == "static_done_external_pending" and not evidence:
            issues.append(f"{rid}: P3 靜態結論缺少真實控制來源證據")
        formal = [e for e in check.get("evidence", []) if isinstance(e, dict)
                  and e.get("kind") in {"source", "configuration"}]
        for j, ev in enumerate(evidence):
            label = f"{rid}: P3 static_evidence[{j}]"
            if not isinstance(ev, dict):
                issues.append(label + " 需具體來源物件")
                continue
            path, lo, hi = ev.get("path"), ev.get("line_start"), ev.get("line_end")
            if (not isinstance(path, str) or path not in known_paths or path not in inspected_paths
                    or type(lo) is not int or type(hi) is not int or lo < 1 or hi < lo):
                issues.append(label + " 路徑或行號無效")
                continue
            if not any(x.get("path") == path and type(x.get("line_start")) is int
                       and type(x.get("line_end")) is int
                       and x["line_start"] <= hi and x["line_end"] >= lo for x in formal):
                issues.append(label + " 未與正式來源證據關聯")
            if _is_weak_source_evidence(
                    {"path": path, "line_start": lo, "line_end": hi}, target) is not False:
                issues.append(label + " 只有宣告、註解或無效行號，無法證實靜態控制")
        gap = record.get("external_gap")
        if not isinstance(gap, dict):
            issues.append(f"{rid}: P3 缺少可核對的外部工件與阻斷原因")
            continue
        category, artifact = gap.get("category"), gap.get("artifact")
        if not isinstance(category, str) or category not in CATEGORIES or not isinstance(artifact, str) or len(artifact.strip()) < 8:
            issues.append(f"{rid}: P3 必須明確命名部署／制度／平台／外部掃描工件")
        question = gap.get("blocking_question")
        explanation = gap.get("why_decisive")
        if not isinstance(question, str) or len(question.strip()) < 16:
            issues.append(f"{rid}: P3 未指出外部工件將決定的具體問題")
        if not isinstance(explanation, str) or len(explanation.strip()) < 24:
            issues.append(f"{rid}: P3 未解釋為何靜態證據無法決定該項符合性")
        boundary = gap.get("manual_boundary")
        expected_boundary = matrix[rid].get("manual_boundary", "")
        if boundary != expected_boundary or (kind == "static_done_external_pending"
                                              and not expected_boundary):
            issues.append(f"{rid}: P3 外部缺口須對應本規則的 manual_boundary")
        reason = str(check.get("decision_reason", ""))
        if "待確認：" not in reason or not isinstance(artifact, str) or artifact not in reason:
            issues.append(f"{rid}: P3 正式 decision_reason 須以「待確認：」明確指名工件")
        if (category == "external_scan" and
                (not isinstance(gap.get("attempted_command"), str)
                 or not gap["attempted_command"].strip()
                 or not isinstance(gap.get("failure_detail"), str)
                 or len(gap["failure_detail"].strip()) < 16)):
            issues.append(f"{rid}: P3 外部掃描缺口須提供實際嘗試的命令與失敗細節")
        if isinstance(artifact, str) and any(word in artifact for word in TEST_ONLY):
            issues.append(f"{rid}: P3 不得僅因缺少非必要動態測試／邊界測試而 review")
        if isinstance(question, str) and any(word in question for word in TEST_ONLY):
            if category != "external_scan":
                issues.append(f"{rid}: P3 請改查證真正的外部阻斷事項，而非泛稱缺少測試")
    return issues
