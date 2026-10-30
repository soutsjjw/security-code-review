#!/usr/bin/env python3
"""完成的程式碼控制 Fail / Review 證據守門；不自行推論漏洞或修改判定。"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from decision_adjudication import DELEGATED_KIND, DELEGATED_RESULT, external_responsibility_errors
from control_proofs import check_source_proofs, REQUIRED_SCENARIOS
from review_core import ANALYSIS_ROOT, REPORT_ROOT, snapshot_fingerprint
from review_decision import is_weak_source_evidence, load_decision_matrix

VERSION = 1
FAILURE_MODES = frozenset({"control_absent", "ineffective_enforcement",
                           "bypass_path", "unsafe_configuration"})
REVIEW_RESULTS = frozenset({"blocked", "not_applicable", "external_boundary"})


def _read_json(path: Path) -> dict:
    import json
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _overlap(a: tuple[str, int, int], b: tuple[str, int, int]) -> bool:
    return a[0] == b[0] and a[1] <= b[2] and b[1] <= a[2]


def _formal_locations(entries: Any) -> set[tuple[str, int, int]]:
    result: set[tuple[str, int, int]] = set()
    if not isinstance(entries, list):
        return result
    for e in entries:
        if (isinstance(e, dict) and isinstance(e.get("path"), str)
                and type(e.get("line_start")) is int
                and type(e.get("line_end")) is int
                and e["line_start"] > 0 and e["line_end"] >= e["line_start"]):
            result.add((e["path"], e["line_start"], e["line_end"]))
    return result


def _text_errors(record: dict, fields: tuple[str, ...], prefix: str) -> list[str]:
    return [f"{prefix}: {field} 須記錄實際控制分支或查證結果"
            for field in fields
            if not isinstance(record.get(field), str)
            or len(record[field].strip()) < 24]


def _required_evidence(target: Path, known: set[str], inspected: set[str],
                       record: dict, keys: tuple[str, ...],
                       rid: str) -> tuple[list[str], dict[str, set[tuple[str, int, int]]]]:
    errors: list[str] = []
    locations: dict[str, set[tuple[str, int, int]]] = {}
    for key in keys:
        issue, proof = check_source_proofs(target, known, inspected, record.get(key), f"{rid}: {key}")
        errors.extend(issue)
        locations[key] = proof
    return errors, locations


def _scenarios(target: Path, known: set[str], inspected: set[str],
               record: dict, rid: str, status: str
               ) -> tuple[list[str], set[tuple[str, int, int]], set[str]]:
    errors: list[str] = []
    cited: set[tuple[str, int, int]] = set()
    observed: set[str] = set()
    rows = record.get("bypass_scenarios")
    if not isinstance(rows, list) or not rows:
        return [f"{rid}: Q3 必須有實際反向繞過情境"], cited, observed
    seen: set[str] = set()
    confirmed = 0
    external = 0
    for i, row in enumerate(rows):
        label = f"{rid}: Q3 繞過情境[{i}]"
        if not isinstance(row, dict):
            errors.append(f"{label} 必須為物件")
            continue
        key = row.get("scenario")
        if not isinstance(key, str) or not key.strip() or key in seen:
            errors.append(f"{label} 情境名稱缺失或重複")
            continue
        seen.add(key)
        observed.add(key)
        outcome = row.get("outcome")
        valid = ({"confirmed_vulnerability", "blocked", "not_applicable"}
                 if status == "fail" else REVIEW_RESULTS)
        if not isinstance(outcome, str) or outcome not in valid:
            errors.append(f"{label} 結果不可為未核對／與規則判定矛盾的狀態")
        else:
            confirmed += outcome == "confirmed_vulnerability"
            external += outcome == "external_boundary"
        reason = row.get("reason")
        if not isinstance(reason, str) or len(reason.strip()) < 24:
            errors.append(f"{label} 缺少具體攻擊路徑及核對結論")
        issue, proof = check_source_proofs(target, known, inspected, row.get("evidence"),
                               f"{label}.evidence")
        errors.extend(issue)
        cited.update(proof)
    if status == "fail" and not confirmed:
        errors.append(f"{rid}: Q3 Fail 至少一條具體確認的繞過／缺失情境")
    if status == "review":
        missing = set(REQUIRED_SCENARIOS.get(rid, ("alternate_or_bypass_path",))) - observed
        if missing:
            errors.append(f"{rid}: Q3 Review 尚未查證必要攻擊情境：" + "、".join(sorted(missing)))
        if not external:
            errors.append(f"{rid}: Q3 Review 須指出哪條情境仍受真正外部證據阻斷")
    return errors, cited, observed


def outcome_errors(target: Path, index: dict, snapshot: dict,
                   checks: list[dict], records: dict, *,
                   audits_override: dict | None = None,
                   assessment_override: dict | None = None) -> list[str]:
    if index.get("control_outcome_version") != VERSION:
        return []
    matrix = load_decision_matrix()
    known_hashes = snapshot.get("source_hashes")
    if not isinstance(known_hashes, dict):
        return ["Q3: 缺少完整來源快照，不得宣稱控制有效性已查核"]
    known = set(known_hashes)
    audit_file = target / ANALYSIS_ROOT / "decision-audits.json"
    audits = audits_override if audits_override is not None else _read_json(audit_file)
    assessment = assessment_override if assessment_override is not None else _read_json(target / REPORT_ROOT / "assessment.json")
    findings = {r["id"]: r for r in assessment.get("findings", [])
                if isinstance(r, dict) and isinstance(r.get("id"), str)}
    errors: list[str] = []
    for check in checks:
        rid = check.get("id")
        if rid not in matrix or (check.get("execution") or {}).get("state") != "completed":
            continue
        status = check.get("status")
        if status not in {"fail", "review"}:
            continue
        formal = _formal_locations([e for e in check.get("evidence", [])
                                    if isinstance(e, dict) and
                                    e.get("kind") in {"source", "configuration"}])
        kind = check.get("review_kind")
        if status == "review" and (kind == "external_only" and
                                   matrix[rid]["mode"] == "external"):
            continue  # 真正的外部控制不應虛構程式碼執行點。
        if status == "review" and kind == DELEGATED_KIND:
            audit = audits.get(rid)
            if (isinstance(audit, dict) and audit.get("status") == "review"
                    and audit.get("review_kind") == DELEGATED_KIND
                    and audit.get("static_result") == DELEGATED_RESULT
                    and not external_responsibility_errors(check, audit, target, known_hashes)):
                continue  # 外部責任已證明；仍由 P3 裁決外部缺口，不能冒充程式碼控制。
            errors.append(f"{rid}: Q3 委外控制責任尚未以真實工件及來源搜尋驗證")
            continue
        if status == "fail" and not formal and matrix[rid]["mode"] == "external":
            continue  # 外部工件的 Fail 交由正式 Finding / 外部證據驗證。
        record = records.get(rid)
        if not isinstance(record, dict):
            errors.append(f"{rid}: Q3 缺少與 {status} 判定相符的控制有效性／繞過路徑證據")
            continue
        if record.get("status") != status:
            errors.append(f"{rid}: Q3 控制結果與正式 {status} 判定不一致")
        if (record.get("git_revision") != snapshot.get("git_revision")
                or record.get("snapshot_fingerprint") != snapshot_fingerprint(snapshot)):
            errors.append(f"{rid}: Q3 控制證據 Git 版本或完整來源指紋已失效")
        inspected_raw = (check.get("execution") or {}).get("inspected_paths")
        inspected = set(x for x in inspected_raw if isinstance(x, str)) \
            if isinstance(inspected_raw, list) else set()
        if not inspected:
            errors.append(f"{rid}: Q3 未提供實際 inspected_paths")
        sections = (("entry_points", "failure_points", "protected_operations") if status == "fail"
                    else ("entry_points", "enforcement_points", "protected_operations"))
        issues, locations = _required_evidence(target, known, inspected, record, sections, rid)
        errors.extend(issues)
        control_key = "failure_points" if status == "fail" else "enforcement_points"
        for pos in record.get(control_key, []) if isinstance(record.get(control_key), list) else []:
            if isinstance(pos, dict) and is_weak_source_evidence(pos, target) is True:
                errors.append(f"{rid}: Q3 {control_key} 只有型別或欄位宣告，不能證明實際控制效果")
        if status == "fail":
            if not isinstance(record.get("failure_mode"), str) or \
                    record["failure_mode"] not in FAILURE_MODES:
                errors.append(f"{rid}: Q3 Fail 缺少有效的缺陷分類")
            errors.extend(_text_errors(record, ("failure_reason", "search_summary"), rid))
            failure = locations["failure_points"]
            if not any(_overlap(p, q) for p in failure for q in formal):
                errors.append(f"{rid}: Q3 Fail 缺陷位置未連結正式檢核來源證據")
            ids = check.get("finding_ids")
            if not isinstance(ids, list) or not ids or not all(
                    isinstance(x, str) and x in findings and
                    rid in (findings[x].get("check_ids") or []) for x in ids):
                errors.append(f"{rid}: Q3 Fail 缺少已保存且能查核的 Finding")
            else:
                evidence = set().union(*(
                    _formal_locations(findings[x].get("evidence", [])) for x in ids
                ))
                if not any(_overlap(p, q) for p in failure for q in evidence):
                    errors.append(f"{rid}: Q3 Fail 缺陷來源與 Finding 證據不一致")
        else:
            errors.extend(_text_errors(record, ("control_condition", "failure_behavior",
                                                 "search_summary"), rid))
            if not any(_overlap(p, q) for p in locations["enforcement_points"] for q in formal):
                errors.append(f"{rid}: Q3 Review 靜態控制位置未連結正式檢核來源證據")
            audit = audits.get(rid)
            gap = audit.get("external_gap") if isinstance(audit, dict) else None
            if (not isinstance(gap, dict) or
                    record.get("external_gap_artifact") != gap.get("artifact") or
                    audit.get("static_result") != "control_satisfied"):
                errors.append(f"{rid}: Q3 Review 未連結已裁決的真實外部阻斷工件")
            if check.get("finding_ids"):
                errors.append(f"{rid}: Q3 Review 已關聯 Finding，須查明是否應 Fail")
        scenario_errors, scenario_proofs, _ = _scenarios(
            target, known, inspected, record, rid, status
        )
        errors.extend(scenario_errors)
        if isinstance(record.get("bypass_scenarios"), list):
            outcome_name = "confirmed_vulnerability" if status == "fail" else "external_boundary"
            anchored = (locations["failure_points"] if status == "fail"
                        else locations["enforcement_points"])
            matched = any(
                _overlap(proof, source)
                for scenario in record["bypass_scenarios"]
                if isinstance(scenario, dict) and scenario.get("outcome") == outcome_name
                for proof in _formal_locations(scenario.get("evidence"))
                for source in anchored
            )
            if not matched:
                errors.append(f"{rid}: Q3 {outcome_name} 情境未與實際失效／控制執行點連結")
        cited = set().union(*locations.values()) | scenario_proofs
        hashes = record.get("source_hashes")
        if not isinstance(hashes, dict) or any(
                hashes.get(path) != known_hashes.get(path) for path, _, _ in cited
        ):
            errors.append(f"{rid}: Q3 控制／繞過證據 SHA256 不符合目前來源快照")
        if not isinstance(record.get("open_issues"), list) or record["open_issues"]:
            errors.append(f"{rid}: Q3 存在尚未完成的程式碼繞過調查，不能標 completed")
    return errors
