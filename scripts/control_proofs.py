#!/usr/bin/env python3
"""控制有效性的最低繞過情境與來源行號證據核對；供上層守門共用，不匯入上層模組。"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from source_reader import read_source_text

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
