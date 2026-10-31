#!/usr/bin/env python3
"""P3 待確認裁決守門：只核對人工證據的可追溯性，不自動改判 pass/fail/review。"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from review_decision import CONFIRMED_DEFECT, load_decision_matrix, is_weak_source_evidence
from source_reader import read_source_text
from review_core import ANALYSIS_ROOT, read_json as _read_json, snapshot_fingerprint

RELATIVE = ANALYSIS_ROOT
INDEX = RELATIVE / "structure-index.json"
SNAPSHOT = RELATIVE / "review-snapshot.json"
AUDITS = RELATIVE / "decision-audits.json"
CONTRACT_VERSION = 1

CONFIG_SUFFIXES = frozenset({".json", ".yaml", ".yml", ".xml", ".config", ".props", ".targets", ".ini"})


def _meaningful_static_source(root: Path, evidence: dict[str, Any]) -> bool:
    """原始碼／組態證據可以來自設定檔；僅檢查內容非空泛，不代表控制安全。"""
    if is_weak_source_evidence(evidence, root) is False:
        return True
    path = evidence["path"]
    if Path(path).suffix.lower() not in CONFIG_SUFFIXES:
        return False
    try:
        lines = read_source_text(root / path)[0].splitlines()
    except (OSError, UnicodeError, ValueError):
        return False
    lo, hi = evidence["line_start"], evidence["line_end"]
    if hi > len(lines):
        return False
    return any(
        len(s := line.strip()) >= 8
        and not s.startswith(("//", "#", "<!--", "/*", "*", "}", "]", "</"))
        for line in lines[lo - 1:hi]
    )


CATEGORIES = frozenset({
    "deployment", "operational_record", "organization_policy", "platform_configuration",
    "external_scan",
})
GENERIC_MISSING_TEST = ("缺少動態測試", "缺乏動態測試", "未提供動態測試",
                        "待補動態測試", "缺少邊界測試", "缺乏邊界測試",
                        "缺少測試案例", "缺乏測試案例", "缺少測試結果", "缺乏測試結果")


# Q1：只對新版結構索引啟用更嚴格的判定品質契約；舊紀錄保留原有驗證。
QUALITY_VERSION = 1
DELEGATED_KIND = "external_responsibility_pending"
DELEGATED_RESULT = "delegated_control"
EXTERNAL_PROOF_KINDS = frozenset({"deployment", "operating_record", "policy", "scan", "test", "interview"})
PLACEHOLDER_ARTIFACT = re.compile(
    r"^(?:[a-z]{2}-\d{2}-)?(?:deployment|policy|external|platform|runtime)"
    r"(?:-or-(?:deployment|policy|external|platform|runtime))?"
    r"(?:-configuration)?-evidence(?:-\d+)?$", re.IGNORECASE,
)
VAGUE_ARTIFACTS = frozenset({
    "待確認資料", "相關文件", "相關證據", "外部證據", "部署或政策證據",
    "部署／政策證據", "待確認外部工件", "待補證據", "policy evidence",
})


def _quality_gap_errors(rule_id: str, rule: dict[str, Any],
                        check: dict[str, Any], record: dict[str, Any]) -> list[str]:
    """限制虛構外部缺口；不讀部署文件、不由字串直接改變安全結論。"""
    errors: list[str] = []
    gap = record.get("external_gap")
    if not isinstance(gap, dict):
        return errors  # 舊有必要欄位驗證已回報。

    artifact = gap.get("artifact")
    if isinstance(artifact, str):
        cleaned = artifact.strip()
        if (PLACEHOLDER_ARTIFACT.fullmatch(cleaned)
                or cleaned.lower() in VAGUE_ARTIFACTS
                or re.search(r"<[^>]+>|\{[^}]+\}|\b(?:TODO|TBD|placeholder)\b",
                             cleaned, re.IGNORECASE)):
            errors.append(f"{rule_id}: Q1 外部工件是佔位／泛稱，必須指名可取得的實際工件")

    owner = gap.get("evidence_owner")
    if not isinstance(owner, str) or len(owner.strip()) < 4:
        errors.append(f"{rule_id}: Q1 須說明外部證據的負責單位或來源平台")

    # 必須描述兩種可驗證、會導致不同結果的情況，避免只寫「缺政策」。
    outcomes = gap.get("decision_outcomes")
    if not isinstance(outcomes, dict):
        errors.append(f"{rule_id}: Q1 缺少外部證據成立／不成立時的判定結果")
    else:
        statuses = []
        reasons = []
        for key in ("if_satisfied", "if_unsatisfied"):
            branch = outcomes.get(key)
            if not isinstance(branch, dict):
                errors.append(f"{rule_id}: Q1 decision_outcomes.{key} 必須為判定物件")
                continue
            status, reason = branch.get("status"), branch.get("reason")
            if not isinstance(status, str) or status not in {"pass", "fail", "na"}:
                errors.append(f"{rule_id}: Q1 decision_outcomes.{key}.status 應為 pass/fail/na")
            else:
                statuses.append(status)
            if not isinstance(reason, str) or len(reason.strip()) < 20:
                errors.append(f"{rule_id}: Q1 decision_outcomes.{key}.reason 須具體描述判定依據")
            else:
                reasons.append(reason.strip())
        if len(statuses) == 2 and statuses[0] == statuses[1]:
            errors.append(f"{rule_id}: Q1 外部證據無法改變結果，不得以 review 阻擋靜態結論")
        if len(reasons) == 2 and reasons[0] == reasons[1]:
            errors.append(f"{rule_id}: Q1 外部證據兩種結果使用相同理由，缺少決定性解釋")

    if gap.get("category") == "organization_policy":
        binding = gap.get("policy_binding")
        if not isinstance(binding, dict) or not isinstance(binding.get("reference"), str) \
                or len(binding["reference"].strip()) < 6 \
                or not isinstance(binding.get("applicability_reason"), str) \
                or len(binding["applicability_reason"].strip()) < 20:
            errors.append(
                f"{rule_id}: Q1 組織政策缺口須提供已知政策識別及對受審系統的適用依據；"
                "未知是否存在額外政策，不應自動造成 review"
            )

    # 自陳已發現缺陷卻標記 control_satisfied，是與正式安全判定的明顯矛盾。
    narratives = "；".join(str(record.get(k, "")) for k in ("static_conclusion",))
    narratives += "；" + str(check.get("decision_reason", ""))
    if check.get("finding_ids") or CONFIRMED_DEFECT.search(narratives):
        errors.append(f"{rule_id}: Q1 review 描述已確認弱點或關聯 Finding，須先依證據改判 fail")
    searched = record.get("searched_paths")
    evidence = record.get("static_evidence")
    if isinstance(searched, list) and isinstance(evidence, list):
        missing = {e["path"] for e in evidence if isinstance(e, dict)
                   and isinstance(e.get("path"), str)} - set(
            x for x in searched if isinstance(x, str)
        )
        if missing:
            errors.append(f"{rule_id}: Q1 靜態證據未列入實際搜尋檔案：" + "、".join(sorted(str(x) for x in missing)))
    return errors


def external_responsibility_errors(
    check: dict[str, Any], record: dict[str, Any], target: Path,
    known_paths: set[str] | dict[str, Any],
) -> list[str]:
    """Verify delegated ownership rather than assuming missing local code is safe."""
    rid = str(check.get("id", "?"))
    evidence = check.get("evidence") or []
    formal = [e for e in evidence if isinstance(e, dict)]
    proof = record.get("responsibility_evidence")
    errors: list[str] = []
    if not isinstance(proof, dict):
        return [f"{rid}: P0 外部控制責任缺少真實、可定位的歸屬證據"]
    kind = proof.get("kind")
    if kind in {"source", "configuration"}:
        path, lo, hi = proof.get("path"), proof.get("line_start"), proof.get("line_end")
        inspected = (check.get("execution") or {}).get("inspected_paths") or []
        if not (isinstance(path, str) and path in known_paths and path in inspected
                and type(lo) is int and type(hi) is int and lo > 0 and hi >= lo
                and any(e.get("kind") in {"source", "configuration"}
                        and e.get("path") == path
                        and type(e.get("line_start")) is int
                        and type(e.get("line_end")) is int
                        and e["line_start"] <= hi and e["line_end"] >= lo for e in formal)
                and _meaningful_static_source(target, proof)):
            errors.append(f"{rid}: P0 責任歸屬來源未連結正式查核或僅為無關宣告")
    elif kind in EXTERNAL_PROOF_KINDS:
        artifact_id = proof.get("artifact_id")
        if not (isinstance(artifact_id, str) and artifact_id.strip()
                and any(e.get("kind") == kind and e.get("artifact_id") == artifact_id
                        for e in formal)):
            errors.append(f"{rid}: P0 外部責任工件未與正式檢核的真實工件識別碼關聯")
    else:
        errors.append(f"{rid}: P0 控制責任證據必須是來源、設定或可追溯外部工件")
    for field in ("responsibility_reason", "repository_search_summary"):
        value = record.get(field)
        if not isinstance(value, str) or len(value.strip()) < 24:
            errors.append(f"{rid}: P0 缺少實際 {field}；不能只以儲存庫無 Workflow 推論委外")
    return errors


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
        "delegated_control_contract": "static/hybrid 可選 external_responsibility_pending：須有可追溯 responsibility_evidence、responsibility_reason、repository_search_summary，且 static_result=delegated_control；未核實歸屬時保持 pending/blocked",
        "quality_gap_fields": ["evidence_owner", "decision_outcomes",
                               "policy_binding（organization_policy 必填）"],
        "note": "審查紀錄不構成自動合格判定；靜態弱點須 fail + Finding",
    }


def adjudication_errors(target: Path, checks: list[dict], *,
                        index_override: dict | None = None,
                        snapshot_override: dict | None = None,
                        audits_override: dict | None = None) -> list[str]:
    """只有 P3 新索引啟用；P2 舊索引不會因工具升級而悄悄重解判定。"""
    index = index_override if index_override is not None else _read_json(target / INDEX, {})
    if not isinstance(index, dict) or index.get("decision_adjudication_version") != CONTRACT_VERSION:
        return []
    snapshot = snapshot_override if snapshot_override is not None else _read_json(target / SNAPSHOT, {})
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("source_hashes"), dict):
        return ["P3: 缺少審查來源快照"]
    audits = audits_override if audits_override is not None else _read_json(target / AUDITS, {})
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
        if kind not in {"static_done_external_pending", "external_only", DELEGATED_KIND}:
            issues.append(f"{rid}: review_kind 須明確分類")
        if matrix[rid]["mode"] != "external" and kind not in {"static_done_external_pending", DELEGATED_KIND}:
            issues.append(f"{rid}: 靜態／混合規則不可直接使用 external_only")
        if kind == DELEGATED_KIND and matrix[rid]["mode"] == "external":
            issues.append(f"{rid}: 純外部規則應使用 external_only，而非委外控制例外")
        if record.get("status") != "review" or record.get("review_kind") != kind:
            issues.append(f"{rid}: P3 判定紀錄的狀態及分類與正式檢核衝突")
        if record.get("git_revision") != snapshot.get("git_revision") or (
                record.get("snapshot_fingerprint") != full_hash):
            issues.append(f"{rid}: P3 判定紀錄的來源版本已失效，須重新查核")
        static_result = record.get("static_result")
        expected = (DELEGATED_RESULT if kind == DELEGATED_KIND else
                    "external_control" if kind == "external_only" else "control_satisfied")
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
        if kind in {"static_done_external_pending", DELEGATED_KIND} and not searched:
            issues.append(f"{rid}: P3 必須核對儲存庫來源與實際控制責任")
        if kind == DELEGATED_KIND:
            issues.extend(external_responsibility_errors(check, record, target, known_paths))
        evidence = record.get("static_evidence")
        if not isinstance(evidence, list):
            issues.append(f"{rid}: P3 static_evidence 必須是來源行號清單")
            evidence = []
        if kind == "static_done_external_pending" and not evidence:
            issues.append(f"{rid}: P3 靜態結論缺少真實控制來源證據")
        if kind == DELEGATED_KIND and evidence:
            issues.append(f"{rid}: P0 委外責任模式不可把宣告或入口位置當成控制有效性的 static_evidence")
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
            if not _meaningful_static_source(
                    target, {"path": path, "line_start": lo, "line_end": hi}):
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
        if isinstance(artifact, str) and any(word in artifact for word in GENERIC_MISSING_TEST):
            issues.append(f"{rid}: P3 不得僅因缺少非必要動態測試／邊界測試而 review")
        if isinstance(question, str) and any(word in question for word in GENERIC_MISSING_TEST):
            if category != "external_scan":
                issues.append(f"{rid}: P3 請改查證真正的外部阻斷事項，而非泛稱缺少測試")
        if index.get("decision_quality_version") == QUALITY_VERSION:
            issues.extend(_quality_gap_errors(rid, matrix[rid], check, record))
    return issues
