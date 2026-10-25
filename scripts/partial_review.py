#!/usr/bin/env python3
"""P2：分類審查的隔離佇列、逐檔覆蓋與分批保存。

本模組只保存由 Agent 實際完成的原始證據，不執行安全分析，也不產生正式報告。
P3/P4 守門尚未接入前，ready_for_report 永遠為 False。
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from datetime import date
from typing import Any

from review_scope import CATEGORY_COUNTS, PARTIAL_ROOT, ScopeError, build_scope_plan, load_catalog
from source_coverage import build_source_coverage
from review_completion import completion_errors
from review_decision import decision_quality_errors
from source_reader import read_source_text
from analysis_candidates import candidate_hits
from assessment_consistency import detect_language_framework
from scope_inventory import detect_projects

STAGED_FILE = Path("analysis/staged/pending.json")
SNAPSHOT_FILE = Path("analysis/source-snapshot.json")
EVIDENCE_KEYS = frozenset({"closures", "control_verifications", "decision_audits",
                           "adversarial_reviews"})
WRITE_KEYS = frozenset({"checks", "file_reviews", "findings", "first_pass_amendments"}) | EVIDENCE_KEYS


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                      separators=(",", ":")).encode("utf-8")).hexdigest()


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _atomic(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".partial-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _git_revision(root: Path) -> str:
    result = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else "not-a-git-repository"


def _snapshot(root: Path) -> dict[str, Any]:
    # 使用正式來源盤點的相同排除範圍，不把 reports/ 或 Skill 當成受測檔案。
    coverage = build_source_coverage({"checks": [], "file_reviews": []}, root)
    files = {path: hashlib.sha256((root / path).read_bytes()).hexdigest()
             for path in coverage["source_paths"]}
    revision = _git_revision(root)
    return {"git_revision": revision, "source_hashes": files,
            "fingerprint": _digest({"git_revision": revision, "source_hashes": files})}


def _category_dir(root: Path, category: str) -> Path:
    if category not in CATEGORY_COUNTS:
        raise ScopeError(f"未支援分類：{category}")
    root = root.resolve()
    directory = root / PARTIAL_ROOT / category
    # 禁止 reports/、partial/ 或分類目錄的 symlink 導向受測專案外部。
    current = directory
    while current != root:
        if current.is_symlink():
            raise ScopeError(f"分類輸出路徑不允許 symbolic link：{current}")
        current = current.parent
    if not directory.resolve().is_relative_to(root):
        raise ScopeError("分類輸出路徑超出受測專案")
    return directory


def _artifact(root: Path, category: str, relative: Path | str) -> Path:
    """只可寫入分類私有目錄；拒絕任何中間 symlink。"""
    directory = _category_dir(root, category)
    path = directory / relative
    if path == directory or not path.resolve().is_relative_to(directory.resolve()):
        raise ScopeError("分類工件路徑無效")
    current = path
    while current != directory:
        if current.is_symlink():
            raise ScopeError(f"分類工件路徑不允許 symbolic link：{current}")
        current = current.parent
    return path


def _category_rules(catalog: dict, category: str) -> list[dict]:
    return [rule for rule in catalog["rules"] if rule["category"] == category]


def _pending_check(rule: dict) -> dict:
    return {
        "id": rule["id"], "status": "review",
        "applicability_reason": "待查證來源與控制責任",
        "decision_reason": "尚未執行審查",
        "evidence": [], "reviewer": "security-code-review-agent",
        "execution": {"state": "pending", "methods": [],
                      "summary": "尚未執行審查，必須查核原始碼與控制流程"},
    }


def _assert_assessment(data: Any, category: str, catalog: dict) -> None:
    expected = [r["id"] for r in _category_rules(catalog, category)]
    if not isinstance(data, dict) or data.get("review_mode") != "partial" or data.get("category") != category:
        raise ScopeError(f"{category}: assessment 的分類身分無效")
    checks = data.get("checks")
    if (not isinstance(checks, list) or len(checks) != len(expected)
            or [c.get("id") for c in checks if isinstance(c, dict)] != expected):
        raise ScopeError(f"{category}: checks 必須按規則主檔順序精確涵蓋 {len(expected)} 項")
    if data.get("ruleset_version") != catalog["ruleset_version"]:
        raise ScopeError(f"{category}: 規則版本不符")
    if (not isinstance(data.get("findings"), list)
            or not isinstance(data.get("file_reviews"), list)):
        raise ScopeError(f"{category}: findings/file_reviews 格式錯誤")
    if data.get("source_snapshot_sha256") is None:
        raise ScopeError(f"{category}: 缺少來源快照識別")


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


def _verify_snapshot(root: Path, directory: Path, assessment: dict) -> None:
    stored_path = _artifact(root, assessment["category"], SNAPSHOT_FILE)
    if not stored_path.is_file():
        raise ScopeError("缺少分類來源快照；不可沿用舊有 completed")
    stored = _load(stored_path)
    if (not isinstance(stored, dict) or stored.get("fingerprint") != _digest({
            "git_revision": stored.get("git_revision"),
            "source_hashes": stored.get("source_hashes"),
        })):
        raise ScopeError("分類來源快照內容損壞")
    if assessment["source_snapshot_sha256"] != stored["fingerprint"]:
        raise ScopeError("assessment 與來源快照識別不一致")
    if _snapshot(root) != stored:
        raise ScopeError("來源檔案或 Git Revision 已異動；拒絕沿用分類審查證據")


def read_category(root: Path, category: str, catalog: dict) -> dict:
    directory = _category_dir(root, category)
    path = directory / "assessment.json"
    if not path.is_file():
        raise ScopeError(f"{category}: 尚無分類進度，請先指定 --init")
    assessment = _load(path)
    _assert_assessment(assessment, category, catalog)
    _verify_snapshot(root, directory, assessment)
    return assessment


def _validate_payload(payload: Any, category: str, catalog: dict) -> None:
    if not isinstance(payload, dict) or not payload or not set(payload) <= WRITE_KEYS:
        raise ScopeError("stage JSON 僅允許非空的 checks、file_reviews、findings")
    allowed = {r["id"] for r in _category_rules(catalog, category)}
    if "first_pass_amendments" in payload:
        amendments = payload["first_pass_amendments"]
        if (not isinstance(amendments, dict) or not amendments
                or any(rid not in allowed or not isinstance(entry, dict)
                       for rid, entry in amendments.items())):
            raise ScopeError("first_pass_amendments 須為本分類規則對應的非空補正紀錄")
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
    from partial_evidence_integrity import (MANIFEST, initialize as seal,
                                            errors as integrity_errors, locked)
    manifest = _artifact(root, category, MANIFEST)
    if not manifest.is_file():
        # 只允許初始乾淨進度自動封存；舊進度不得被默默採信。
        seal(root, category)
    with locked(root, category):
        problems = integrity_errors(root, category)
        if problems:
            raise ScopeError("；".join(problems))
        return _stage_locked(root, category, input_path, catalog)


def _stage_locked(root: Path, category: str, input_path: Path, catalog: dict) -> Path:
    current = read_category(root, category, catalog)
    payload = _load(input_path)
    _validate_payload(payload, category, catalog)
    directory = _category_dir(root, category)
    pending = _artifact(root, category, STAGED_FILE)
    if "adversarial_reviews" in payload:
        from partial_review_safety import BASELINE
        if not _artifact(root, category, BASELINE).is_file():
            raise ScopeError("第二輪證據須先固定第一輪結論：--begin-second-pass")
    if pending.exists():
        raise ScopeError(f"{category}: 已有未整合的 staged 交易；請先 --integrate")
    # O_EXCL 阻擋兩個 Agent 同時啟動 staging（不允許失敗時覆寫）。
    pending.parent.mkdir(parents=True, exist_ok=True)
    from partial_review_safety import EVIDENCE_FILES
    evidence_sha = {key: _digest(_load(_artifact(root, category, rel)))
                    if _artifact(root, category, rel).is_file() else None
                    for key, rel in EVIDENCE_FILES.items()}
    body = {"category": category, "base_sha256": _digest(current),
            "evidence_sha256": evidence_sha,
            "snapshot_sha256": current["source_snapshot_sha256"], "payload": payload}
    with pending.open("x", encoding="utf-8") as handle:
        json.dump(body, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    return pending


def integrate(root: Path, category: str, catalog: dict, *, allow_revision: bool = False,
              amend_first_pass: bool = False) -> dict:
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
    if allow_revision and amend_first_pass:
        raise ScopeError("第一輪補正與第二輪矛盾修訂不得混用")
    if bool(payload.get("first_pass_amendments")) != amend_first_pass:
        raise ScopeError("第一輪補正須同時提供 --amend-first-pass 與 first_pass_amendments")
    from partial_review_safety import EVIDENCE_FILES
    evidence_paths = {key: _artifact(root, category, rel)
                      for key, rel in EVIDENCE_FILES.items()}
    actual_evidence = {key: _load(path) if path.is_file() else {}
                       for key, path in evidence_paths.items()}
    expected_sha = staged.get("evidence_sha256")
    if not isinstance(expected_sha, dict) or any(
        expected_sha.get(key) != (_digest(actual_evidence[key]) if evidence_paths[key].is_file() else None)
        for key in EVIDENCE_FILES):
        raise ScopeError("分類安全證據已由其他工作異動，拒絕覆寫 staged 交易")
    from partial_review_safety import BASELINE
    from adversarial_recheck import digest as rule_digest
    baseline_path = _artifact(root, category, BASELINE)
    baseline = _load(baseline_path) if baseline_path.is_file() else None
    amendments = payload.get("first_pass_amendments", {})
    if amend_first_pass and baseline is not None:
        raise ScopeError("第一輪已固定 baseline；不得使用 --amend-first-pass")
    reviewed_paths = {}
    if amend_first_pass:
        from partial_first_pass import verify_amendments
        reviewed_paths = verify_amendments(
            root, category, amendments, {r["id"] for r in _category_rules(catalog, category)})
    first_pass_changed: set[str] = set()
    revisions = {}
    for check in payload.get("checks", []):
        old = next(item for item in current["checks"] if item["id"] == check["id"])
        if (old.get("execution") or {}).get("state") != "completed" or check == old:
            continue
        rid = check["id"]
        if amend_first_pass:
            if rid not in reviewed_paths:
                raise ScopeError(f"{rid}: 修訂 completed 規則需要真實第一輪補正證據")
            if old.get("status") == "fail" and check.get("status") != "fail":
                raise ScopeError(f"{rid}: 已確認 Fail 不得藉第一輪補正降級")
            if old.get("status") == "fail" and not set(old.get("finding_ids", [])) <= set(check.get("finding_ids", [])):
                raise ScopeError(f"{rid}: 補正不得移除既有 Fail 的 Finding 關聯")
            if check.get("status") == "fail":
                findings = {f["id"]: f for f in [*current["findings"], *payload.get("findings", [])]
                            if isinstance(f, dict) and isinstance(f.get("id"), str)}
                refs = check.get("finding_ids")
                if (not isinstance(refs, list) or not refs or any(
                        fid not in findings or rid not in (findings[fid].get("check_ids") or [])
                        for fid in refs)):
                    raise ScopeError(f"{rid}: 第一輪修訂為 Fail 必須保留有效 Finding")
            first_pass_changed.add(rid)
            continue
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
            if previous is not None and previous != item:
                if amend_first_pass and rid in reviewed_paths:
                    first_pass_changed.add(rid)
                elif not allow_revision or rid not in revisions:
                    raise ScopeError(f"{key}: {rid} 既有安全證據不得靜默覆寫")
            elif amend_first_pass and rid in reviewed_paths and previous != item:
                first_pass_changed.add(rid)
            merged_evidence[key][rid] = item

    merged = json.loads(json.dumps(current, ensure_ascii=False))
    by_id = {r["id"]: r for r in merged["checks"]}
    for check in payload.get("checks", []):
        previous = by_id[check["id"]]
        if (previous["execution"]["state"] == "completed"
                and check != previous and check["id"] not in revisions
                and check["id"] not in first_pass_changed):
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
                related_rules = old_rules | new_rules
                for item in (old_row, row):
                    screening = item.get("category_screening", {}).get(category, {})
                    related_rules.update(screening.get("rule_ids", []))
                    related_rules.update(
                        x.get("rule_id") for x in item.get("candidate_exclusions", [])
                        if isinstance(x, dict))
                source_valid = (key == "file_reviews" and
                                row.get("sha256") == _snapshot(root)["source_hashes"].get(row[identity]))
                first_pass_file_ok = (key == "file_reviews" and amend_first_pass
                                      and source_valid
                                      and any(row[identity] in paths for paths in reviewed_paths.values())
                                      and related_rules <= set(reviewed_paths))
                if first_pass_file_ok:
                    first_pass_changed.update(
                        rid for rid, paths in reviewed_paths.items() if row[identity] in paths)
                elif (key != "file_reviews" or not allow_revision or not revisions
                      or not (old_rules | new_rules) <= set(revisions)
                      or old_row.get("sha256") != row.get("sha256")):
                    raise ScopeError(f"{key}: {row[identity]} 已存在不同證據，拒絕覆寫")
            existing[row[identity]] = row
        merged[key] = list(existing.values())
    _assert_assessment(merged, category, catalog)
    # 尚未滿足安全守門的批次仍可持久保存，但不得藉此宣稱安全審查完成。
    if amend_first_pass and (not first_pass_changed or set(amendments) != first_pass_changed):
        raise ScopeError("第一輪補正紀錄必須精確對應實際修改的規則或既有證據")
    archive_update = None
    if amend_first_pass:
        from partial_evidence_integrity import FIRST_PASS_HISTORY
        first_pass_archive = {
            "category": category,
            "source_snapshot_sha256": current["source_snapshot_sha256"],
            "amendments": amendments,
            "previous_checks": {r["id"]: r for r in current["checks"]
                                if r["id"] in first_pass_changed},
            "previous_safety_records": {
                key: {rid: entries[rid] for rid in first_pass_changed if rid in entries}
                for key, entries in actual_evidence.items()},
            "previous_file_reviews": {
                r["path"]: r for r in current["file_reviews"]
                if any(r["path"] in paths for paths in reviewed_paths.values())},
        }
        historical = (FIRST_PASS_HISTORY / (_digest(first_pass_archive)[:32] + ".json")).as_posix()
        if _artifact(root, category, historical).exists():
            raise ScopeError("第一輪補正歷史已存在；不得重複提交")
        archive_update = (historical, first_pass_archive)
    if revisions:
        from partial_review_safety import HISTORY
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
            archive_update = ((HISTORY / digest_name).as_posix(), archive)
    updates = {EVIDENCE_FILES[key].as_posix(): merged_evidence[key]
               for key in sorted(EVIDENCE_KEYS & set(payload))}
    if archive_update is not None:
        updates[archive_update[0]] = archive_update[1]
    updates["assessment.json"] = merged
    from partial_evidence_integrity import _sha, commit
    receipt = commit(root, category, updates,
                     event=("first-pass-amendment" if amend_first_pass else
                            "review-batch-with-correction" if revisions else "review-batch"),
                     staged_path=pending, staged_sha256=_sha(pending.read_bytes()))
    return {"category": category, "saved_checks": len(payload.get("checks", [])),
            "saved_files": len(payload.get("file_reviews", [])),
            "saved_findings": len(payload.get("findings", [])),
            "saved_safety_records": {key: len(payload[key]) for key in EVIDENCE_KEYS & set(payload)},
            "corrected_rule_ids": sorted(revisions),
            "first_pass_amended_rule_ids": sorted(first_pass_changed),
            "integrity_sequence": receipt["sequence"],
            "ready_for_report": False}


def queue(root: Path, categories: tuple[str, ...], catalog: dict, batch_size: int,
          *, detail_id: str | None = None, compact: bool = False) -> dict:
    from review_queue import (load_tacert_v2_checks, load_owasp_2025_categories,
                              STANDARD_GUIDES)
    from review_decision import load_decision_matrix
    from control_effectiveness import guidance as control_guidance
    from decision_adjudication import guidance as adjudication_guidance
    from adversarial_recheck import guidance as adversarial_guidance
    from system_baseline import source_review_hints
    from web_guide import web_guide_review_hints
    from web_appendix1 import appendix_review_hints
    from web_headers import header_review_hints
    rules = catalog["rules"]
    maps = {} if compact else {
        "tacert_v2_checks": load_tacert_v2_checks(rules),
        "owasp_2025_categories": load_owasp_2025_categories(rules),
        "system_baseline_v13_controls": source_review_hints(rules),
        "web_guide_v32_checks": web_guide_review_hints(rules),
        "web_guide_v32_appendix1": appendix_review_hints(rules),
        "web_guide_v32_appendix3": header_review_hints(rules),
    }
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
                    "control_effectiveness_guidance": control_guidance(r["id"]),
                    "decision_adjudication_guidance": adjudication_guidance(r["id"]),
                    "adversarial_guidance": adversarial_guidance(r["id"]),
                })
                item.update({name: mapping[r["id"]] for name, mapping in maps.items()})
                if detail_id:
                    item["standard_documents"] = [
                        path for name, path in STANDARD_GUIDES.items() if item.get(name)]
            next_checks.append(item)
        complete = len(remaining) == 0 and not coverage["missing_source_file_count"]
        complete = complete and not coverage["review_integrity_errors"] and not quality
        from partial_review_safety import validate as validate_partial
        safety = validate_partial(root, category, catalog)
        import re
        recheck = sorted({
            rid for message in safety["safety_integrity_errors"]
            for rid in re.findall(r"\b(?:AC|AU|IN|CR|EH|LG|DP|PD|BC|SI)-\d{2}\b", message)
            if rid in by_id
        })
        if not remaining and not detail_id:
            next_checks = [{
                "id": rid, "title": by_id[rid].get("title", next(
                    (rule["title"] for rule in selected_rules if rule["id"] == rid), "")),
                "current_state": "completed", "requires_first_pass_recheck": True,
            } for rid in recheck[:batch_size]]
        results.append({
            "category": category, "total": len(checks),
            "completed": sum((c.get("execution") or {}).get("state") == "completed" for c in checks),
            "pending": sum((c.get("execution") or {}).get("state") == "pending" for c in checks),
            "blocked": sum((c.get("execution") or {}).get("state") == "blocked" for c in checks),
            "findings_saved": len(assessment["findings"]),
            "remaining_ids": [r["id"] for r in remaining],
            "recheck_rule_ids": recheck, "safety_error_count": len(safety["safety_integrity_errors"]),
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
