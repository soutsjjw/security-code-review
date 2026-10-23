#!/usr/bin/env python3
"""P2 控制有效性守門。只檢查人工紀錄與真實來源是否一致，絕不自行判斷安全。"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from review_decision import load_decision_matrix
from source_reader import read_source_text

CONTRACT_VERSION = 1
RELATIVE = Path("reports/security-code-review")
INDEX = RELATIVE / "analysis/structure-index.json"
SNAPSHOT = RELATIVE / "analysis/review-snapshot.json"
VERIFICATIONS = RELATIVE / "analysis/control-verifications.json"

# 各規則必須明確涵蓋的典型繞過面。這是最低追查範圍，不等於全部攻擊路徑。
REQUIRED_SCENARIOS: dict[str, tuple[str, ...]] = {
    "AC-01": ("expired_session", "alternate_access_path", "configuration_override"),
    "AC-02": ("token_reuse", "alternate_logout_path"),
    "AC-04": ("least_privilege_bypass", "alternate_entry"),
    "AC-06": ("unauthenticated_entry", "policy_bypass"),
    "AC-08": ("horizontal_access", "vertical_access", "alternate_entry", "direct_data_access"),
    "AU-03": ("repeated_attempt", "alternate_login_entry"),
    "AU-06": ("reset_token_replay", "reset_identity_bypass"),
    "AU-08": ("alternate_storage_path", "unsalted_or_weak_hash"),
    "AU-09": ("mfa_skip_path", "recovery_flow_bypass"),
    "IN-01": ("untrusted_sql_input", "alternate_query_path"),
    "IN-02": ("untrusted_output", "alternate_render_path"),
    "IN-03": ("missing_csrf_token", "alternate_write_path"),
    "IN-04": ("untrusted_command_argument", "alternate_execution_path"),
    "IN-05": ("invalid_input", "alternate_input_path"),
    "IN-06": ("oversized_or_disallowed_upload", "alternate_upload_path"),
    "IN-07": ("traversal_encoding", "symlink_or_root_escape"),
    "IN-08": ("internal_destination", "redirect_or_dns_rebinding"),
    "CR-05": ("header_omission", "alternate_response_path"),
    "CR-06": ("insecure_cookie_attributes", "alternate_cookie_issue"),
    "SI-03": ("untrusted_payload", "alternate_deserialization_path"),
}


def guidance(rule_id: str) -> dict[str, Any]:
    matrix = load_decision_matrix()
    if rule_id not in matrix:
        raise ValueError(f"未知規則：{rule_id}")
    info = matrix[rule_id]
    return {
        "required_for_pass": info["mode"] != "external",
        "pass_condition": info["pass_condition"],
        "manual_boundary": info["manual_boundary"],
        "required_scenarios": list(REQUIRED_SCENARIOS.get(rule_id, ("alternate_or_bypass_path",))),
        "evidence_contract": "核對 entry_points、enforcement_points、protected_operations、"
                             "bypass_scenarios 與 source_evidence；任何未解繞過不得標 pass",
        "note": "僅為審查工作紀錄，不會自動判斷安全或從候選索引繼承 pass",
    }


def _read_json(path: Path, default: Any) -> Any:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else default


def _location_errors(root: Path, known: set[str], inspected: set[str],
                     entry: Any, label: str) -> tuple[list[str], tuple[str, int, int] | None]:
    if not isinstance(entry, dict):
        return [f"{label}: 證據須為含 path/line_start/line_end 的物件"], None
    path = entry.get("path")
    lo, hi = entry.get("line_start"), entry.get("line_end")
    if not isinstance(path, str) or path not in known or path not in inspected:
        return [f"{label}: 來源路徑不存在於快照或未列入 execution.inspected_paths"], None
    if type(lo) is not int or type(hi) is not int or lo < 1 or hi < lo:
        return [f"{label}: 行號必須為合法來源範圍"], None
    source = (root / path).resolve()
    if not source.is_relative_to(root.resolve()) or not source.is_file():
        return [f"{label}: 禁止讀取來源根目錄以外的檔案"], None
    try:
        lines = read_source_text(source)[0].splitlines()
    except (OSError, UnicodeError, ValueError):
        return [f"{label}: 無法讀取來源內容"], None
    if hi > len(lines):
        return [f"{label}: 行號超出實際檔案長度"], None
    if not any(line.strip() and not line.lstrip().startswith(("//", "#", "*", "<!--"))
               for line in lines[lo - 1:hi]):
        return [f"{label}: 來源僅有空白或註解，無法佐證控制效果"], None
    return [], (path, lo, hi)


def _proofs(root: Path, known: set[str], inspected: set[str],
            items: Any, label: str) -> tuple[list[str], set[tuple[str, int, int]]]:
    if not isinstance(items, list) or not items:
        return [f"{label}: 至少需要一筆具行號的真實來源證據"], set()
    errs: list[str] = []
    located: set[tuple[str, int, int]] = set()
    for i, item in enumerate(items):
        issue, location = _location_errors(root, known, inspected, item, f"{label}[{i}]")
        errs.extend(issue)
        if location is not None:
            located.add(location)
    return errs, located


def verification_errors(target: Path, checks: list[dict]) -> list[str]:
    """只在 P2 版本的來源索引啟動，既有快照以 recheck 流程遷移。"""
    index = _read_json(target / INDEX, {})
    if not isinstance(index, dict) or index.get("control_effectiveness_version") != CONTRACT_VERSION:
        return []
    snapshot = _read_json(target / SNAPSHOT, {})
    if not isinstance(snapshot, dict):
        return ["P2: 缺少來源快照，不得宣稱控制已驗證"]
    known = set(snapshot.get("source_hashes") or {})
    records = _read_json(target / VERIFICATIONS, {})
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
        if record.get("status") != "pass":
            errors.append(f"{rid}: P2 控制驗證紀錄與規則 pass 不一致")
        if record.get("git_revision") != snapshot.get("git_revision"):
            errors.append(f"{rid}: P2 控制驗證的 Git Revision 與快照不一致")
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
    return errors
