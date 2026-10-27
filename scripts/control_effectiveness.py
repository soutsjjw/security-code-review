#!/usr/bin/env python3
"""P2 控制有效性守門。只檢查人工紀錄與真實來源是否一致，絕不自行判斷安全。"""
from __future__ import annotations

import argparse
import hashlib
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
    "AC-07": ("directory_listing", "sensitive_static_file_access"),
    "AU-01": ("alternate_registration", "password_change_bypass"),
    "AU-02": ("password_reuse", "alternate_credential_change"),
    "AU-07": ("user_enumeration_response", "error_message_leak"),
    "AU-10": ("spoofed_source_header", "proxy_trust_override"),
    "CR-01": ("plaintext_fallback", "tls_termination_boundary"),
    "CR-02": ("weak_algorithm_path", "encryption_downgrade"),
    "CR-03": ("secret_config_fallback", "environment_override"),
    "CR-04": ("plaintext_storage_path", "encryption_key_handling"),
    "EH-01": ("exception_detail_leak", "alternate_error_response"),
    "EH-02": ("unhandled_endpoint_exception", "background_task_failure"),
    "EH-03": ("exception_cleanup_path", "resource_lifetime"),
    "EH-05": ("debug_config_override", "diagnostics_exposure"),
    "LG-01": ("security_event_without_log", "alternate_auth_entry"),
    "LG-02": ("admin_action_without_audit", "audit_sink_failure"),
    "LG-08": ("sensitive_data_in_log", "exception_logging"),
    "PD-02": ("unmasked_detail_view", "unmasked_export"),
    "PD-03": ("plaintext_personal_data_transport", "alternate_channel"),
    "PD-04": ("personal_data_access_without_log", "export_audit_gap"),
    "PD-05": ("unencrypted_persistence", "alternate_storage"),
    "PD-06": ("unauthorized_remote_pii_access", "alternate_endpoint"),
    "PD-07": ("incomplete_deletion", "cached_or_backup_copy"),
    "AC-03": ("admin_route_exposure", "network_source_override"),
    "AC-05": ("privileged_process_identity", "container_runtime_override"),
    "AU-04": ("plaintext_credential_channel", "tls_termination_bypass"),
    "AU-05": ("captcha_bypass_endpoint", "server_side_verification"),
    "EH-04": ("critical_error_without_alert", "alert_delivery_failure"),
    "EH-06": ("default_credential", "insecure_default_configuration"),
    "LG-03": ("log_tampering", "log_integrity_verification"),
    "LG-04": ("inconsistent_log_structure", "alternate_logging_sink"),
    "LG-05": ("log_capacity_exhaustion", "rotation_failure"),
    "LG-06": ("clock_drift", "timestamp_source_override"),
    "LG-07": ("unauthorized_log_access", "backup_restore_integrity"),
    "LG-09": ("audit_sink_unavailable", "audit_failure_response"),
    "LG-10": ("hash_verification_bypass", "integrity_key_substitution"),
    "DP-01": ("vulnerable_dependency", "transitive_dependency"),
    "DP-02": ("default_third_party_secret", "component_configuration_override"),
    "DP-03": ("unnecessary_listening_service", "port_exposure_override"),
    "DP-04": ("unsupported_version", "unpatched_dependency"),
    "PD-01": ("collection_without_legal_basis", "excessive_data_collection"),
    "PD-08": ("breach_detection_gap", "notification_process_failure"),
    "BC-01": ("backup_execution_failure", "backup_restore_failure"),
    "BC-02": ("production_secret_in_test", "environment_boundary_bypass"),
    "BC-03": ("single_failure_domain", "failover_not_operational"),
    "BC-04": ("outdated_security_document", "undocumented_configuration_change"),
    "BC-05": ("source_backup_inaccessible", "backup_integrity_failure"),
    "BC-06": ("unreviewed_change", "unauthorized_release_path"),
    "BC-07": ("failover_drill_not_executed", "recovery_objective_not_verified"),
    "SI-01": ("untrusted_pipeline_trigger", "credential_exposure_in_ci"),
    "SI-02": ("missing_subresource_integrity", "third_party_resource_override"),

}


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


def snapshot_fingerprint(snapshot: dict[str, Any]) -> str:
    """將完整 Git 版本與所有來源 SHA256 固定為單一指紋，避免跨檔新增時沿用舊 pass。"""
    basis = {"git_revision": snapshot.get("git_revision"),
             "source_hashes": snapshot.get("source_hashes")}
    raw = json.dumps(basis, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


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


def _external_pass_errors(
    target: Path, check: dict, record: dict, known: set[str],
    snapshot: dict, scenarios_required: set[str],
) -> list[str]:
    """Pass from proved external enforcement, never from package declarations."""
    from decision_adjudication import external_responsibility_errors, EXTERNAL_PROOF_KINDS
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


def verification_errors(target: Path, checks: list[dict], *
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
    from control_outcome_evidence import outcome_errors
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
