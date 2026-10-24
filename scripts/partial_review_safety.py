#!/usr/bin/env python3
"""分類審查 P3：共享結構索引、第一輪證據守門、第二輪反向複核。

不產生 pass/fail、Finding 或 HTML；安全結論必須由 Agent 真實讀碼提供。
部分報告仍由 P4 處理；ready_for_report 必須保持 false。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from review_scope import PARTIAL_ROOT, ScopeError
from review_completion import completion_errors
from review_decision import decision_quality_errors
from source_coverage import build_source_coverage
from review_safety import closure_errors, rule_scopes
from control_effectiveness import verification_errors, snapshot_fingerprint
from decision_adjudication import adjudication_errors
from adversarial_recheck import second_pass_errors, digest
from partial_review import (_artifact, _category_dir, _category_rules, _load, _atomic,
                            _digest, _snapshot, read_category, STAGED_FILE)

STRUCTURE = PARTIAL_ROOT / "_shared/analysis/structure-index.json"
INDEX_SEAL = PARTIAL_ROOT / "_shared/analysis/index-integrity.json"
BASELINE = Path("analysis/first-pass-baseline.json")
CLOSURES = Path("analysis/rule-closures.json")
VERIFICATIONS = Path("analysis/control-verifications.json")
AUDITS = Path("analysis/decision-audits.json")
REVIEWS = Path("analysis/adversarial-reviews.json")
HISTORY = Path("analysis/second-pass-history")
EVIDENCE_FILES = {"closures": CLOSURES, "control_verifications": VERIFICATIONS,
                  "decision_audits": AUDITS, "adversarial_reviews": REVIEWS}


def _shared_path(root: Path) -> Path:
    root = root.resolve()
    path = root / STRUCTURE
    # 與每分類防護一致，禁止輸出路徑透過 symlink 穿越目標根目錄。
    current = path
    while current != root:
        if current.is_symlink():
            raise ScopeError("共享來源索引路徑不允許 symbolic link")
        current = current.parent
    if not path.resolve().is_relative_to(root):
        raise ScopeError("共享索引路徑超出受測根目錄")
    return path


def prepare_index(root: Path, catalog: dict) -> dict:
    """只產生 partial/_shared 的結構索引；不改動正式審查 analysis。"""
    from analysis_prepare import (ADAPTERS, INDEX_VERSION, ROSLYN_VERSION,
                                  DOTNET_EXTENSIONS, CANDIDATE_VERSION, _run_roslyn,
                                  cross_file_call_hints, probe_codegraph, probe_roslyn)
    from review_relationships import build_relationships
    from analysis_candidates import candidate_hits
    from source_reader import read_source_text
    from review_scope import validate_catalog
    validate_catalog(catalog)
    root = root.resolve()
    adapter = ADAPTERS[0]
    detection = adapter.detect(root)
    snapshot = _snapshot(root)
    files = snapshot["source_hashes"]
    if not detection["supported"] or any(path.endswith(".vue") for path in files):
        raise ScopeError("分類結構索引僅支援 .NET Core／現代 .NET；不允許略過不支援框架")
    index_path = _shared_path(root)
    seal = root / INDEX_SEAL
    if index_path.is_file():
        old = _load(index_path)
        seal_obj = _load(seal) if seal.is_file() else None
        if (isinstance(old, dict) and old.get("source_hashes") == files
                and old.get("git_revision") == snapshot["git_revision"]
                and old.get("schema_version") == INDEX_VERSION
                and isinstance(seal_obj, dict)
                and seal_obj.get("index_sha256") == _digest(old)
                and seal_obj.get("source_snapshot_sha256") == snapshot["fingerprint"]):
            return {"index_path": STRUCTURE.as_posix(), "reused": True,
                    "source_file_count": len(files), "complete_security_review": False}
        raise ScopeError("共享索引的來源版本已變更，拒絕隱性覆寫；請先核對並重新開始受影響審查")
    if seal.exists():
        raise ScopeError("共用索引驗證紀錄存在，但索引缺失；拒絕覆寫")
    codegraph, roslyn = probe_codegraph(root), probe_roslyn()
    csharp = sorted(p for p in files if p.endswith(".cs"))
    parsed, errors = _run_roslyn(root, csharp, roslyn)
    hints = cross_file_call_hints(parsed)
    candidates = {p: candidate_hits(p, read_source_text(root / p)[0])
                  for p in files if Path(p).suffix.lower() in DOTNET_EXTENSIONS}
    relationships = build_relationships(root, sorted(files), hints)
    current = _snapshot(root)
    if current != snapshot:
        raise ScopeError("建立索引時來源版本異動，拒絕保存不一致結果")
    payload = {
        "schema_version": INDEX_VERSION,
        "control_effectiveness_version": 1, "control_outcome_version": 1,
        "decision_adjudication_version": 1, "decision_quality_version": 1,
        "cross_file_evidence_version": 1, "adversarial_second_pass_version": 1,
        "adversarial_quality_version": 1,
        "adapter": adapter.name, "roslyn_version": ROSLYN_VERSION,
        "candidate_version": CANDIDATE_VERSION,
        "sdk_version": roslyn.get("sdk_version"),
        "source_hashes": files, "git_revision": snapshot["git_revision"],
        "rule_candidates": candidates, "roslyn_files": parsed,
        "cross_file_call_hints": hints, "typed_relationships": relationships,
        "codegraph": codegraph, "roslyn": {k: v for k, v in roslyn.items() if k != "executable"},
        "roslyn_errors": errors,
        "warning": "僅為來源結構候選；不得因此完成任何安全規則。",
    }
    _atomic(index_path, payload)
    _atomic(seal, {"index_sha256": _digest(payload),
                   "source_snapshot_sha256": snapshot["fingerprint"]})
    return {"index_path": STRUCTURE.as_posix(), "reused": False,
            "source_file_count": len(files), "roslyn_errors": errors[:10],
            "complete_security_review": False}


def _evidence(root: Path, category: str, key: str) -> dict:
    path = _artifact(root, category, EVIDENCE_FILES[key])
    if not path.is_file():
        return {}
    data = _load(path)
    if not isinstance(data, dict):
        raise ScopeError(f"{category}: {key} 應為規則 ID 對應的物件")
    return data


def _index(root: Path, assessment: dict) -> tuple[dict, list[str]]:
    path = _shared_path(root)
    if not path.is_file():
        return {}, ["尚未建立分類共用的來源結構索引；先執行 --prepare"]
    obj = _load(path)
    seal_path = root / INDEX_SEAL
    seal = _load(seal_path) if seal_path.is_file() else None
    snap = _snapshot(root)
    if (not isinstance(seal, dict) or seal.get("index_sha256") != _digest(obj)
            or seal.get("source_snapshot_sha256") != snap["fingerprint"]):
        return {}, ["共用結構索引完整性校驗失敗，拒絕未經驗證的候選關聯資料"]
    if (not isinstance(obj, dict) or obj.get("source_hashes") != snap["source_hashes"]
            or obj.get("git_revision") != snap["git_revision"]):
        return {}, ["共用結構索引與 Git／來源快照不一致，拒絕以失效候選驗證安全結論"]
    if assessment.get("source_snapshot_sha256") != snap["fingerprint"]:
        return {}, ["分類來源快照已異動，不可沿用既有完成證據"]
    for key in ("control_effectiveness_version", "control_outcome_version",
                "cross_file_evidence_version", "decision_adjudication_version",
                "decision_quality_version", "adversarial_second_pass_version",
                "adversarial_quality_version"):
        if obj.get(key) != 1:
            return {}, [f"來源索引缺少必須的 {key} 安全證據契約"]
    return obj, []


def _snap(root: Path) -> dict:
    current = _snapshot(root)
    return {"schema_version": 1, "git_revision": current["git_revision"],
            "source_hashes": current["source_hashes"], "excluded_paths": []}


def _first_pass(root: Path, category: str, assessment: dict, index: dict) -> list[str]:
    checks = assessment["checks"]
    data = _snap(root)
    closure = _evidence(root, category, "closures")
    controls = _evidence(root, category, "control_verifications")
    audits = _evidence(root, category, "decision_audits")
    issues = closure_errors(root, assessment, index_override=index,
                            snapshot_override=data, closures_override=closure)
    issues += verification_errors(root, checks, index_override=index, snapshot_override=data,
                                  records_override=controls, audits_override=audits,
                                  assessment_override=assessment)
    issues += adjudication_errors(root, checks, index_override=index,
                                  snapshot_override=data, audits_override=audits)
    # 一旦第一輪所有規則標示完成，啟用原本的逐條品質／來源驗證。
    if all((c.get("execution") or {}).get("state") == "completed" for c in checks):
        issues += completion_errors(checks)
        issues += decision_quality_errors(checks, source_root=root)
        coverage = build_source_coverage(assessment, root, selected_categories=(category,))
        issues += coverage["review_integrity_errors"]
        if coverage["missing_source_file_count"]:
            issues.append(f"{category}: 尚有 {coverage['missing_source_file_count']} 個來源檔未經分類逐檔查證")
    return issues


def begin_second_pass(root: Path, category: str, catalog: dict) -> dict:
    assessment = read_category(root, category, catalog)
    index, problems = _index(root, assessment)
    if problems:
        raise ScopeError("；".join(problems))
    checks = assessment["checks"]
    if any((c.get("execution") or {}).get("state") != "completed" for c in checks):
        raise ScopeError(f"{category}: 第一輪 {len(checks)} 項尚未全數完成")
    if _artifact(root, category, STAGED_FILE).exists():
        raise ScopeError(f"{category}: 尚有未整合的工作暫存，禁止開始第二輪")
    problems = _first_pass(root, category, assessment, index)
    if problems:
        raise ScopeError("第一輪安全證據尚未結案：" + "；".join(problems[:8]))
    from adversarial_recheck import CONTRACT_VERSION
    baseline = {"schema_version": CONTRACT_VERSION,
                "snapshot_fingerprint": snapshot_fingerprint(_snap(root)),
                "checks": {c["id"]: {"status": c["status"], "digest": digest(c),
                                     "decision_reason": c.get("decision_reason", "")}
                           for c in checks}}
    path = _artifact(root, category, BASELINE)
    if path.is_file():
        previous = _load(path)
        if previous != baseline:
            raise ScopeError("第一輪固定判定已有差異；不可覆寫。請查明版本及矛盾來源")
        return {"category": category, "already_existed": True,
                "rule_count": len(checks), "ready_for_report": False}
    _atomic(path, baseline)
    return {"category": category, "already_existed": False,
            "rule_count": len(checks), "ready_for_report": False}


def validate(root: Path, category: str, catalog: dict) -> dict:
    assessment = read_category(root, category, catalog)
    index, errors = _index(root, assessment)
    checks = assessment["checks"]
    remaining = [c["id"] for c in checks
                 if (c.get("execution") or {}).get("state") != "completed"]
    if index:
        errors += _first_pass(root, category, assessment, index)
    coverage = build_source_coverage(assessment, root, selected_categories=(category,))
    baseline_path = _artifact(root, category, BASELINE)
    baseline = _load(baseline_path) if baseline_path.is_file() else None
    reviews = _evidence(root, category, "adversarial_reviews")
    audits = _evidence(root, category, "decision_audits")
    if index and not remaining:
        errors += second_pass_errors(
            root, assessment, index_override=index, snapshot_override=_snap(root),
            baseline_override=baseline if baseline is not None else {},
            reviews_override=reviews, audits_override=audits)
    pending_second = []
    if not baseline:
        pending_second = [c["id"] for c in checks]
    else:
        originals = baseline.get("checks", {})
        for check in checks:
            rec = reviews.get(check["id"])
            if (not isinstance(rec, dict) or rec.get("final_digest") != digest(check)
                    or check["id"] not in originals):
                pending_second.append(check["id"])
        for error in errors:
            prefix = error.split(":", 1)[0]
            if prefix in originals and prefix not in pending_second:
                pending_second.append(prefix)
    return {
        "category": category, "first_pass_complete": not remaining and not _first_pass(
            root, category, assessment, index) if index else False,
        "remaining_ids": remaining,
        "second_pass": {"baseline_ready": baseline is not None, "pending_ids": pending_second,
                        "pending_count": len(pending_second)},
        "safety_integrity_errors": errors,
        "safety_valid": not errors and not remaining and not pending_second
                        and coverage["missing_source_file_count"] == 0,
        "ready_for_report": False,
    }
