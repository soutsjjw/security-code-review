#!/usr/bin/env python3
"""P2 控制有效性守門。只檢查人工紀錄與真實來源是否一致，絕不自行判斷安全。"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from review_decision import load_decision_matrix
from control_outcome_evidence import outcome_errors
from control_proofs import REQUIRED_SCENARIOS, _location_errors, _proofs
from decision_adjudication import external_responsibility_errors, EXTERNAL_PROOF_KINDS
from review_core import read_json as _read_json, REPORT_ROOT, snapshot_fingerprint

CONTRACT_VERSION = 1
RELATIVE = REPORT_ROOT
INDEX = RELATIVE / "analysis/structure-index.json"
SNAPSHOT = RELATIVE / "analysis/review-snapshot.json"
VERIFICATIONS = RELATIVE / "analysis/control-verifications.json"


def guidance(rule_id: str) -> dict[str, Any]:
    matrix = load_decision_matrix()
    if rule_id not in matrix:
        raise ValueError(f"未知規則：{rule_id}")
    info = matrix[rule_id]
    return {
        "required_for_pass": info["mode"] != "external",
        "external_verified_pass_contract": "需真實 responsibility_evidence、control_evidence、版本快照、完整必要繞過情境與 formal evidence 交叉引用；不可用缺少 Workflow 或宣告當控制有效",
        "required_for_fail": "具原始碼／組態來源的已確認缺陷",
        "required_for_review": "靜態／混合控制已有靜態結論且確有外部阻斷",
        "pass_condition": info["pass_condition"],
        "manual_boundary": info["manual_boundary"],
        "required_scenarios": list(REQUIRED_SCENARIOS.get(rule_id, ("alternate_or_bypass_path",))),
        "evidence_contract": "核對 entry_points、enforcement_points、protected_operations、"
                             "bypass_scenarios 與 source_evidence；任何未解繞過不得標 pass",
        "note": "僅為審查工作紀錄，不會自動判斷安全或從候選索引繼承 pass",
    }


def _external_pass_errors(
    target: Path, check: dict, record: dict, known: set[str],
    snapshot: dict, scenarios_required: set[str],
) -> list[str]:
    """Pass from proved external enforcement, never from package declarations."""
    rid = check["id"]
    issues = external_responsibility_errors(check, record, target, known)
    inspected = (check.get("execution") or {}).get("inspected_paths") or []
    if not inspected:
        issues.append(f"{rid}: P0 委外有效控制仍須有實際儲存庫檢閱範圍")
    if (record.get("git_revision") != snapshot.get("git_revision")
            or record.get("snapshot_fingerprint") != snapshot_fingerprint(snapshot)):
        issues.append(f"{rid}: P0 外部控制查證與來源快照版本不一致")
    proof = record.get("control_evidence")
    formal = [e for e in (check.get("evidence") or []) if isinstance(e, dict)]
    def matches(item: Any) -> bool:
        return (isinstance(item, dict) and item.get("kind") in EXTERNAL_PROOF_KINDS
                and isinstance(item.get("artifact_id"), str) and item["artifact_id"].strip()
                and any(e.get("kind") == item["kind"]
                        and e.get("artifact_id") == item["artifact_id"] for e in formal))
    if not matches(proof):
        issues.append(f"{rid}: P0 外部有效控制需獨立可追溯的實際運作工件，責任歸屬不等於控制有效")
    for field in ("control_condition", "failure_behavior", "search_summary"):
        value = record.get(field)
        if not isinstance(value, str) or len(value.strip()) < 24:
            issues.append(f"{rid}: P0 外部控制缺少具體 {field} 查證內容")
    scenarios = record.get("bypass_scenarios")
    if not isinstance(scenarios, list):
        scenarios = []
    seen: set[str] = set()
    for item in scenarios:
        if not isinstance(item, dict):
            issues.append(f"{rid}: P0 外部控制繞過情境必須為物件")
            continue
        key = item.get("scenario")
        if not isinstance(key, str) or key in seen:
            issues.append(f"{rid}: P0 外部控制繞過情境重複或缺少名稱")
            continue
        seen.add(key)
        if (item.get("outcome") not in {"blocked", "not_applicable"}
                or not isinstance(item.get("reason"), str)
                or len(item["reason"].strip()) < 24
                or not matches(item.get("evidence"))):
            issues.append(f"{rid}: P0 {key} 缺少可追溯的外部繞過防護證據")
    if scenarios_required - seen:
        issues.append(f"{rid}: P0 尚未核實的外部繞過情境：" +
                      "、".join(sorted(scenarios_required - seen)))
    if not isinstance(record.get("open_issues"), list) or record["open_issues"]:
        issues.append(f"{rid}: P0 外部控制仍有未完成的查證，不可宣稱 pass")
    return issues


def verification_errors(target: Path, checks: list[dict], *,
                        index_override: dict | None = None,
                        snapshot_override: dict | None = None,
                        records_override: dict | None = None,
                        audits_override: dict | None = None,
                        assessment_override: dict | None = None) -> list[str]:
    """只在 P2 版本的來源索引啟動，既有快照以 recheck 流程遷移。"""
    index = index_override if index_override is not None else _read_json(target / INDEX, {})
    if not isinstance(index, dict) or index.get("control_effectiveness_version") != CONTRACT_VERSION:
        return []
    snapshot = snapshot_override if snapshot_override is not None else _read_json(target / SNAPSHOT, {})
    if not isinstance(snapshot, dict):
        return ["P2: 缺少來源快照，不得宣稱控制已驗證"]
    known = set(snapshot.get("source_hashes") or {})
    records = records_override if records_override is not None else _read_json(target / VERIFICATIONS, {})
    if not isinstance(records, dict):
        return ["P2: control-verifications.json 必須是規則 ID 對應的 JSON 物件"]
    matrix = load_decision_matrix()
    errors: list[str] = []
    for check in checks:
        rid = check.get("id")
        if rid not in matrix or (check.get("execution") or {}).get("state") != "completed":
            continue
        if check.get("status") != "pass" or matrix[rid]["mode"] == "external":
            continue
        record = records.get(rid)
        if not isinstance(record, dict):
            errors.append(f"{rid}: P2 缺少控制存在、有效性與繞過路徑的查核紀錄")
            continue
        if record.get("control_proof_mode") == "external_verified":
            if record.get("status") != "pass":
                errors.append(f"{rid}: P0 外部有效控制紀錄狀態與 pass 不一致")
            errors.extend(_external_pass_errors(
                target, check, record, known, snapshot,
                set(REQUIRED_SCENARIOS.get(rid, ("alternate_or_bypass_path",))),
            ))
            continue
        if record.get("status") != "pass":
            errors.append(f"{rid}: P2 控制驗證紀錄與規則 pass 不一致")
        if record.get("git_revision") != snapshot.get("git_revision"):
            errors.append(f"{rid}: P2 控制驗證的 Git Revision 與快照不一致")
        if record.get("snapshot_fingerprint") != snapshot_fingerprint(snapshot):
            errors.append(f"{rid}: P2 控制驗證的完整來源快照指紋已失效，必須重查可能的旁路")
        inspected = set((check.get("execution") or {}).get("inspected_paths") or [])
        if not inspected:
            errors.append(f"{rid}: P2 沒有可核對的 inspected_paths")
        locations: dict[str, set[tuple[str, int, int]]] = {}
        for field in ("entry_points", "enforcement_points", "protected_operations"):
            issue, located = _proofs(target, known, inspected, record.get(field), f"{rid}: {field}")
            errors.extend(issue)
            locations[field] = located
        for field in ("control_condition", "failure_behavior", "search_summary"):
            value = record.get(field)
            if not isinstance(value, str) or len(value.strip()) < 20:
                errors.append(f"{rid}: P2 缺少具體 {field}，不得只確認安全 API 存在")
        scanned_hashes = record.get("source_hashes")
        cited_paths = {x[0] for group in locations.values() for x in group}
        if not isinstance(scanned_hashes, dict) or any(
            scanned_hashes.get(path) != snapshot["source_hashes"].get(path)
            for path in cited_paths
        ):
            errors.append(f"{rid}: P2 證據來源 SHA256 與快照不一致")
        # 至少一個控制執行位置必須與正式 check.evidence 有行號交集。
        evidence = [
            e for e in check.get("evidence", [])
            if isinstance(e, dict) and e.get("kind") in {"source", "configuration"}
            and type(e.get("line_start")) is int and type(e.get("line_end")) is int
        ]
        if locations["enforcement_points"] and not any(
            e.get("path") == path and e["line_start"] <= hi and e["line_end"] >= lo
            for path, lo, hi in locations["enforcement_points"] for e in evidence
        ):
            errors.append(f"{rid}: P2 控制實際執行位置未與正式來源證據連結")
        scenarios = record.get("bypass_scenarios")
        if not isinstance(scenarios, list) or not scenarios:
            errors.append(f"{rid}: P2 缺少已核對的繞過情境")
            continue
        required = set(REQUIRED_SCENARIOS.get(rid, ("alternate_or_bypass_path",)))
        seen: set[str] = set()
        for i, scenario in enumerate(scenarios):
            if not isinstance(scenario, dict):
                errors.append(f"{rid}: 繞過情境[{i}] 格式錯誤")
                continue
            kind = scenario.get("scenario")
            if not isinstance(kind, str) or not kind.strip() or kind in seen:
                errors.append(f"{rid}: 繞過情境[{i}] 重複或沒有識別名稱")
                continue
            seen.add(kind)
            if scenario.get("outcome") not in {"blocked", "not_applicable"}:
                errors.append(f"{rid}: {kind} 尚未證明被阻擋或確實不適用；不可 pass")
            reason = scenario.get("reason")
            if not isinstance(reason, str) or len(reason.strip()) < 20:
                errors.append(f"{rid}: {kind} 缺少具體反向追查理由")
            issue, located = _proofs(target, known, inspected, scenario.get("evidence"),
                                     f"{rid}: {kind}.evidence")
            errors.extend(issue)
            cited_paths.update(x[0] for x in located)
        missing = required - seen
        if missing:
            errors.append(f"{rid}: P2 尚未核對的必要繞過情境：{', '.join(sorted(missing))}")
        if not isinstance(scanned_hashes, dict) or any(
            scanned_hashes.get(path) != snapshot["source_hashes"].get(path)
            for path in cited_paths
        ):
            errors.append(f"{rid}: P2 繞過情境證據 SHA256 與快照不一致")
        open_issues = record.get("open_issues")
        if not isinstance(open_issues, list) or open_issues:
            errors.append(f"{rid}: P2 有未解決的繞過路徑或未提供 open_issues=[]，不可 pass")
    # 新索引要求完成的程式碼型 Fail / Review 同樣有控制有效性證據。
    # Pass 仍走既有 P2 契約，外部控制不用捏造來源執行點。
    errors.extend(outcome_errors(target, index, snapshot, checks, records,
                                 audits_override=audits_override,
                                 assessment_override=assessment_override))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="顯示 P2 全來源快照指紋；不產生任何安全判定")
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--snapshot-fingerprint", action="store_true", required=True)
    args = parser.parse_args()
    snapshot = _read_json(args.target.resolve() / SNAPSHOT, None)
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("source_hashes"), dict):
        parser.error("缺少可用 review-snapshot.json；須先執行 analysis_prepare.py")
    print(snapshot_fingerprint(snapshot))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
