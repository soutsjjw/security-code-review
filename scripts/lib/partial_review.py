#!/usr/bin/env python3
"""P2：分類審查的隔離佇列、逐檔覆蓋與分批保存。

本模組只保存由 Agent 實際完成的原始證據，不執行安全分析，也不產生正式報告。
P3/P4 守門尚未接入前，ready_for_report 永遠為 False。
"""
from __future__ import annotations

import json
from pathlib import Path
from datetime import date
from typing import Any

from review_scope import CATEGORY_COUNTS, PARTIAL_ROOT, ScopeError, build_scope_plan
from source_coverage import build_source_coverage
from review_completion import completion_errors
from review_decision import decision_quality_errors, load_decision_matrix
from source_reader import read_source_text
from analysis_candidates import candidate_hits
from assessment_consistency import detect_language_framework
from scope_inventory import detect_projects
from review_core import (canonical_digest as _digest, write_json_atomic as _atomic,
                         write_json_exclusive)
from partial_review_store import (BASELINE, EVIDENCE_FILES, HISTORY, SNAPSHOT_FILE, STAGED_FILE,
                                  _artifact, _assert_assessment, _category_dir, _category_rules,
                                  _load, _snapshot, _verify_snapshot, read_category)
from partial_review_safety import validate as validate_partial
from adversarial_recheck import digest as rule_digest
import rule_guidance

EVIDENCE_KEYS = frozenset({"closures", "control_verifications", "decision_audits",
                           "adversarial_reviews"})
WRITE_KEYS = frozenset({"checks", "file_reviews", "findings"}) | EVIDENCE_KEYS


def _pending_check(rule: dict) -> dict:
    return {
        "id": rule["id"], "status": "review",
        "applicability_reason": "待查證來源與控制責任",
        "decision_reason": "尚未執行審查",
        "evidence": [], "reviewer": "security-code-review-agent",
        "execution": {"state": "pending", "methods": [],
                      "summary": "尚未執行審查，必須查核原始碼與控制流程"},
    }


def initialize(root: Path, categories: tuple[str, ...], catalog: dict) -> list[str]:
    plan = build_scope_plan(root, categories, catalog)
    snapshot = _snapshot(root)
    created: list[str] = []
    for row in plan["category_reports"]:
        cat = row["category"]
        directory = _category_dir(root, cat)
        assessment_file = directory / "assessment.json"
        snapshot_file = _artifact(root, cat, SNAPSHOT_FILE)
        project_file = directory / "project.json"
        if assessment_file.exists() or snapshot_file.exists():
            # 不補寫／修補既有半套資料：未齊者要求人工調查，避免隱性覆蓋。
            if not assessment_file.is_file() or not snapshot_file.is_file():
                raise ScopeError(f"{cat}: 分類進度不完整，不允許重新初始化覆寫")
            existing = _load(assessment_file)
            _assert_assessment(existing, cat, catalog)
            _verify_snapshot(root, directory, existing)
            continue
        if directory.exists() and any(directory.iterdir()):
            raise ScopeError(f"{cat}: 分類目錄已有其他資料，拒絕覆寫")
        assessment = {
            "review_mode": "partial", "category": cat, "ruleset_version": catalog["ruleset_version"],
            "project_id": root.name, "git_revision": snapshot["git_revision"],
            "assessment_date": date.today().isoformat(),
            "scope": f"僅 {cat} 分類；來源盤點仍包含所有適用程式與組態",
            "source_snapshot_sha256": snapshot["fingerprint"],
            "checks": [_pending_check(r) for r in _category_rules(catalog, cat)],
            "file_reviews": [], "findings": [], "scope_details": {"projects": detect_projects(root)},
        }
        _atomic(snapshot_file, snapshot)
        _atomic(assessment_file, assessment)
        if not project_file.exists():
            _atomic(project_file, {"name": root.name, "language_framework": detect_language_framework(root)})
        created.append(cat)
    return created


def _validate_payload(payload: Any, category: str, catalog: dict) -> None:
    if not isinstance(payload, dict) or not payload or not set(payload) <= WRITE_KEYS:
        raise ScopeError("stage JSON 僅允許非空的 checks、file_reviews、findings")
    allowed = {r["id"] for r in _category_rules(catalog, category)}
    for key, id_key in (("checks", "id"), ("file_reviews", "path"), ("findings", "id")):
        rows = payload.get(key, [])
        if not isinstance(rows, list):
            raise ScopeError(f"{key} 必須為陣列")
        if any(not isinstance(row, dict) or not isinstance(row.get(id_key), str)
               or not row[id_key] for row in rows):
            raise ScopeError(f"{key} 包含無效物件／識別")
        values = [row[id_key] for row in rows]
        if len(values) != len(set(values)):
            raise ScopeError(f"{key} 存在重複識別")
    for key in EVIDENCE_KEYS & set(payload):
        rows = payload[key]
        if not isinstance(rows, dict) or not rows:
            raise ScopeError(f"{key} 必須是非空的規則 ID 對應物件")
        for rid, entry in rows.items():
            if rid not in allowed or not isinstance(entry, dict):
                raise ScopeError(f"{key}: 含有未選分類規則或無效證據：{rid}")
    for check in payload.get("checks", []):
        if check["id"] not in allowed:
            raise ScopeError(f"不可寫入未選分類規則：{check['id']}")
        state = (check.get("execution") or {}).get("state")
        if state not in ("pending", "completed", "blocked"):
            raise ScopeError(f"{check['id']}: execution.state 無效")
        if check.get("status") not in ("pass", "fail", "review", "na"):
            raise ScopeError(f"{check['id']}: status 無效")
        if state == "completed":
            issues = completion_errors([check]) + decision_quality_errors([check])
            if issues:
                raise ScopeError("; ".join(issues[:3]))
    for row in payload.get("file_reviews", []):
        screening = row.get("category_screening")
        if not isinstance(screening, dict) or set(screening) != {category}:
            raise ScopeError(f"{category}: file_reviews 僅可包含本分類 category_screening")
        if (not isinstance(row.get("rule_reviews"), list)
                or any(not isinstance(item, dict) or item.get("rule_id") not in allowed
                       for item in row["rule_reviews"])):
            raise ScopeError("file_reviews 含未選分類規則")
        if any(not isinstance(item, dict) or item.get("rule_id") not in allowed
               for item in row.get("candidate_exclusions", [])):
            raise ScopeError("candidate_exclusions 含未選分類規則")
        for item in screening.values():
            if not isinstance(item, dict) or not isinstance(item.get("rule_ids"), list) or any(
                    rid not in allowed for rid in item["rule_ids"]):
                raise ScopeError("category_screening 含未選分類規則")
    for finding in payload.get("findings", []):
        refs = finding.get("check_ids")
        if not isinstance(refs, list) or not refs or any(rid not in allowed for rid in refs):
            raise ScopeError(f"Finding {finding['id']} 不可引用未選分類規則")


def stage(root: Path, category: str, input_path: Path, catalog: dict) -> Path:
    current = read_category(root, category, catalog)
    payload = _load(input_path)
    _validate_payload(payload, category, catalog)
    directory = _category_dir(root, category)
    pending = _artifact(root, category, STAGED_FILE)
    if "adversarial_reviews" in payload:
        if not _artifact(root, category, BASELINE).is_file():
            raise ScopeError("第二輪證據須先固定第一輪結論：--begin-second-pass")
    if pending.exists():
        raise ScopeError(f"{category}: 已有未整合的 staged 交易；請先 --integrate")
    # O_EXCL 阻擋兩個 Agent 同時啟動 staging（不允許失敗時覆寫）。
    pending.parent.mkdir(parents=True, exist_ok=True)
    evidence_sha = {key: _digest(_load(_artifact(root, category, rel)))
                    if _artifact(root, category, rel).is_file() else None
                    for key, rel in EVIDENCE_FILES.items()}
    body = {"category": category, "base_sha256": _digest(current),
            "evidence_sha256": evidence_sha,
            "snapshot_sha256": current["source_snapshot_sha256"], "payload": payload}
    write_json_exclusive(pending, body)
    return pending


def integrate(root: Path, category: str, catalog: dict, *, allow_revision: bool = False) -> dict:
    current = read_category(root, category, catalog)
    directory = _category_dir(root, category)
    pending = _artifact(root, category, STAGED_FILE)
    if not pending.is_file():
        raise ScopeError(f"{category}: 沒有待整合的 staged 交易")
    staged = _load(pending)
    if (staged.get("category") != category or staged.get("base_sha256") != _digest(current)
            or staged.get("snapshot_sha256") != current["source_snapshot_sha256"]):
        raise ScopeError("分類暫存版本與目前來源／assessment 不一致，拒絕整合")
    payload = staged["payload"]
    _validate_payload(payload, category, catalog)
    evidence_paths = {key: _artifact(root, category, rel)
                      for key, rel in EVIDENCE_FILES.items()}
    actual_evidence = {key: _load(path) if path.is_file() else {}
                       for key, path in evidence_paths.items()}
    expected_sha = staged.get("evidence_sha256")
    if not isinstance(expected_sha, dict) or any(
        expected_sha.get(key) != (_digest(actual_evidence[key]) if evidence_paths[key].is_file() else None)
        for key in EVIDENCE_FILES):
        raise ScopeError("分類安全證據已由其他工作異動，拒絕覆寫 staged 交易")
    baseline_path = _artifact(root, category, BASELINE)
    baseline = _load(baseline_path) if baseline_path.is_file() else None
    revisions = {}
    for check in payload.get("checks", []):
        old = next(item for item in current["checks"] if item["id"] == check["id"])
        if (old.get("execution") or {}).get("state") != "completed" or check == old:
            continue
        rid = check["id"]
        first = (baseline or {}).get("checks", {}).get(rid)
        reviewed = payload.get("adversarial_reviews", {}).get(rid)
        if (not allow_revision or not isinstance(first, dict)
                or not isinstance(reviewed, dict) or reviewed.get("outcome") != "corrected"
                or reviewed.get("baseline_digest") != first.get("digest")
                or reviewed.get("final_digest") != rule_digest(check)
                or reviewed.get("final_status") != check.get("status")
                or not reviewed.get("contradictions")
                or (check.get("execution") or {}).get("state") != "completed"):
            raise ScopeError(f"{rid}: 修正 completed 判定須 --allow-revision 與第二輪具體矛盾裁決")
        if old.get("status") == "fail" and check.get("status") != "fail":
            raise ScopeError(f"{rid}: 已確認 Fail 不得藉第二輪修訂降級")
        if check.get("status") == "fail":
            available = {f["id"]: f for f in [*current["findings"], *payload.get("findings", [])]
                         if isinstance(f, dict) and isinstance(f.get("id"), str)}
            refs = check.get("finding_ids")
            if (not isinstance(refs, list) or not refs or any(
                    not isinstance(fid, str) or fid not in available
                    or rid not in (available[fid].get("check_ids") or []) for fid in refs)):
                raise ScopeError(f"{rid}: 第二輪修訂為 Fail 必須同批或既有保存可追查 Finding")
        revisions[rid] = old
    if allow_revision and not revisions:
        raise ScopeError("--allow-revision 必須包含實際改判及裁決，不得用於一般覆寫")
    merged_evidence = {key: dict(actual_evidence[key]) for key in EVIDENCE_FILES}
    for key in EVIDENCE_KEYS & set(payload):
        for rid, item in payload[key].items():
            previous = merged_evidence[key].get(rid)
            if previous is not None and previous != item and (not allow_revision or rid not in revisions):
                raise ScopeError(f"{key}: {rid} 既有安全證據不得靜默覆寫")
            merged_evidence[key][rid] = item

    merged = json.loads(json.dumps(current, ensure_ascii=False))
    by_id = {r["id"]: r for r in merged["checks"]}
    for check in payload.get("checks", []):
        previous = by_id[check["id"]]
        if (previous["execution"]["state"] == "completed"
                and check != previous and check["id"] not in revisions):
            raise ScopeError(f"{check['id']}: 已完成判定不可靜默覆寫；需先人工複核")
        by_id[check["id"]] = check
    merged["checks"] = [by_id[r["id"]] for r in _category_rules(catalog, category)]
    for key, identity in (("file_reviews", "path"), ("findings", "id")):
        existing = {r[identity]: r for r in merged[key]}
        for row in payload.get(key, []):
            if row[identity] in existing and existing[row[identity]] != row:
                old_row = existing[row[identity]]
                old_rules = {i.get("rule_id") for i in old_row.get("rule_reviews", []) if isinstance(i, dict)}
                new_rules = {i.get("rule_id") for i in row.get("rule_reviews", []) if isinstance(i, dict)}
                if (key != "file_reviews" or not allow_revision or not revisions
                        or not (old_rules | new_rules) <= set(revisions)
                        or old_row.get("sha256") != row.get("sha256")):
                    raise ScopeError(f"{key}: {row[identity]} 已存在不同證據，拒絕覆寫")
            existing[row[identity]] = row
        merged[key] = list(existing.values())
    _assert_assessment(merged, category, catalog)
    # 未完成逐檔核驗的資料可以分批保存，但不可因此輸出任何完成報告。
    if revisions:
        archive = {
            "category": category, "source_snapshot_sha256": current["source_snapshot_sha256"],
            "previous_checks": revisions,
            "previous_safety_records": {
                key: {rid: existing[rid] for rid in revisions if rid in existing}
                for key, existing in actual_evidence.items()
            },
            "previous_file_reviews": {r["path"]: r for r in current["file_reviews"]},
        }
        digest_name = _digest(archive)[:32] + ".json"
        archive_path = _artifact(root, category, HISTORY / digest_name)
        if archive_path.exists():
            if _load(archive_path) != archive:
                raise ScopeError("第二輪修訂歷史紀錄存在衝突")
        else:
            _atomic(archive_path, archive)
    for key in EVIDENCE_KEYS & set(payload):
        _atomic(evidence_paths[key], merged_evidence[key])
    _atomic(directory / "assessment.json", merged)
    pending.unlink()
    return {"category": category, "saved_checks": len(payload.get("checks", [])),
            "saved_files": len(payload.get("file_reviews", [])),
            "saved_findings": len(payload.get("findings", [])),
            "saved_safety_records": {key: len(payload[key]) for key in EVIDENCE_KEYS & set(payload)},
            "corrected_rule_ids": sorted(revisions),
            "ready_for_report": False}


def queue(root: Path, categories: tuple[str, ...], catalog: dict, batch_size: int,
          *, detail_id: str | None = None, compact: bool = False) -> dict:
    rules = catalog["rules"]
    maps = {} if compact else rule_guidance.standard_maps(rules)
    decision = load_decision_matrix() if not compact else {}
    if detail_id and detail_id.split("-")[0] not in categories:
        raise ScopeError(f"未選分類規則不可查詢：{detail_id}")
    results = []
    for category in categories:
        if detail_id and not detail_id.startswith(category + "-"):
            continue
        assessment = read_category(root, category, catalog)
        checks = assessment["checks"]
        by_id = {c["id"]: c for c in checks}
        selected_rules = _category_rules(catalog, category)
        remaining = [r for r in selected_rules
                     if (by_id[r["id"]].get("execution") or {}).get("state") != "completed"]
        if detail_id and detail_id not in by_id:
            raise ScopeError(f"未知規則 ID：{detail_id}")
        next_rules = ([next(r for r in selected_rules if r["id"] == detail_id)]
                      if detail_id else remaining[:batch_size])
        coverage = build_source_coverage(assessment, root, selected_categories=(category,))
        quality = []
        if not remaining:
            quality = completion_errors(checks) + decision_quality_errors(checks, source_root=root)
        candidates = []
        for path in coverage["missing_source_paths"][:30]:
            try:
                hits = [h["rule_id"] for h in candidate_hits(path, read_source_text(root / path)[0])
                        if h["rule_id"] in by_id]
            except (OSError, UnicodeError):
                continue
            if hits:
                candidates.append({"path": path, "rule_ids": hits})
        next_checks = []
        for r in next_rules:
            item = {"id": r["id"], "title": r["title"],
                    "current_state": (by_id[r["id"]].get("execution") or {}).get("state", "pending"),
                    "search_targets": r.get("inspection", {}).get("search_targets", [])}
            if not compact:
                item.update({
                    "inspection_hints": r.get("inspection", {}).get("legacy_inspection_hints", []),
                    "verification_method": r.get("inspection", {}).get("verification_method", ""),
                    "applicable_when": r.get("applicability", {}).get("must_assess_when", ""),
                    "na_when": r.get("applicability", {}).get("may_be_not_applicable_when", ""),
                    "decision_guidance": decision[r["id"]],
                    **rule_guidance.guidance_fields(r["id"]),
                })
                item.update({name: mapping[r["id"]] for name, mapping in maps.items()})
                if detail_id:
                    item["standard_documents"] = rule_guidance.standard_documents(item)
            next_checks.append(item)
        complete = len(remaining) == 0 and not coverage["missing_source_file_count"]
        complete = complete and not coverage["review_integrity_errors"] and not quality
        safety = validate_partial(root, category, catalog)
        results.append({
            "category": category, "total": len(checks),
            "completed": sum((c.get("execution") or {}).get("state") == "completed" for c in checks),
            "pending": sum((c.get("execution") or {}).get("state") == "pending" for c in checks),
            "blocked": sum((c.get("execution") or {}).get("state") == "blocked" for c in checks),
            "findings_saved": len(assessment["findings"]),
            "remaining_ids": [r["id"] for r in remaining],
            "next_checks": next_checks, "next_source_paths": coverage["missing_source_paths"][:30],
            "next_source_candidates": candidates[:15],
            "source_coverage": {k: coverage[k] for k in
                                ("source_file_count", "reviewed_source_file_count",
                                 "missing_source_file_count", "missing_by_type")},
            "review_integrity_errors": coverage["review_integrity_errors"][:20],
            "rule_integrity_errors": quality[:30],
            "safety_integrity_errors": safety["safety_integrity_errors"][:30],
            "second_pass": safety["second_pass"],
            "first_pass_complete": safety["first_pass_complete"],
            "safety_valid": safety["safety_valid"],
            "preliminary_coverage_ready": bool(complete),
            "ready_for_report": False,
            "assessment_path": (PARTIAL_ROOT / category / "assessment.json").as_posix(),
        })
    return {
        "review_mode": "partial", "selected_categories": list(categories),
        "selected_rule_count": sum(CATEGORY_COUNTS[cat] for cat in categories),
        "category_queues": results,
        "ready_for_report": False,
        "notice": "所有選定分類安全驗證通過後，使用 complete_review.py --categories 產生各分類 HTML／JSON；ready_for_report 固定為 false，不代表部分報告不可產生。",
    }
