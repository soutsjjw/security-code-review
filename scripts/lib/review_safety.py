#!/usr/bin/env python3
"""單代理審查的六項 P0 守門：來源快照、規則責任、證據閉包、暫存及衝突整合。

來源快照、規則責任與證據閉包由下層 review_snapshot 提供；本模組負責暫存、整合、
快照更新與 CLI。僅處理審查資料，絕不自動作安全判定，也不建立或啟動子代理。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import date
import sys
from pathlib import Path
from typing import Any

from snapshot_impact import affected_rules, source_delta
from review_core import read_json as integrity_read, snapshot_fingerprint, write_json_atomic as _write
import review_snapshot
from adversarial_recheck import second_pass_errors
from batch_evidence_gate import batch_quality_errors
from evidence_integrity import MANIFEST as integrity_manifest


def safety_errors(target: Path, assessment: dict) -> list[str]:
    from control_effectiveness import verification_errors
    from decision_adjudication import adjudication_errors
    from evidence_integrity import errors as evidence_integrity_errors
    errors = (evidence_integrity_errors(target) + review_snapshot.snapshot_errors(target) + review_snapshot.closure_errors(target, assessment)
              + verification_errors(target, assessment.get("checks", []))
              + adjudication_errors(target, assessment.get("checks", []))
              + second_pass_errors(target, assessment))
    outstanding = review_snapshot.read_report_json(review_snapshot.report_dir(target) / review_snapshot.RECHECK, {}) or {}
    ids = outstanding.get("rule_ids", [])
    if ids:
        errors.append("來源異動後仍有待重新檢核的規則：" + "、".join(ids[:15]))
    return errors


def _fingerprint(finding: dict) -> str:
    evidence = finding.get("evidence") or []
    locations = sorted((str(e.get("path") or ""), e.get("line_start") or 0,
                        e.get("line_end") or 0) for e in evidence if isinstance(e, dict))
    basis = json.dumps([finding.get("title", "").strip().casefold(),
                        sorted(finding.get("check_ids", [])), locations],
                       sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def stage(target: Path, payload_path: Path) -> str:
    failures = review_snapshot.snapshot_errors(target)
    if failures:
        raise ValueError("；".join(failures))
    if not (review_snapshot.report_dir(target) / review_snapshot.SNAPSHOT).exists():
        raise ValueError("請先執行 analysis_prepare.py 建立來源快照")
    from evidence_integrity import errors as evidence_integrity_errors
    failures = evidence_integrity_errors(target)
    if failures:
        raise ValueError("；".join(failures))
    # 新流程 opt-in；既有審查續跑預設仍走原交易契約。
    if os.environ.get("SECURITY_CODE_REVIEW_EXECUTION_MODE") == "optimized":
        from execution_boundary import require_clean
        require_clean(target, batch_id=hashlib.sha256(str(payload_path).encode("utf-8")).hexdigest()[:24],
                      stage="first_pass")
    payload = review_snapshot.read_report_json(payload_path)
    if not isinstance(payload, dict):
        raise ValueError("暫存資料必須為 JSON 物件")
    known_sections = {"file_reviews", "checks", "findings", "finding_revisions", "fail_withdrawals", "closures",
                      "control_verifications", "decision_audits", "adversarial_reviews", "second_pass_samples", "recheck_proof"}
    unexpected = set(payload) - known_sections
    if unexpected:
        raise ValueError("暫存資料包含未知欄位，禁止靜默丟棄：" + "、".join(sorted(unexpected)))
    for key in ("file_reviews", "checks", "findings", "finding_revisions", "fail_withdrawals", "closures", "control_verifications", "decision_audits", "adversarial_reviews", "second_pass_samples", "recheck_proof"):
        is_map = key in {"finding_revisions", "fail_withdrawals", "closures", "control_verifications", "decision_audits", "adversarial_reviews", "second_pass_samples", "recheck_proof"}
        value = payload.get(key, {} if is_map else [])
        if not isinstance(value, dict if is_map else list):
            raise ValueError(f"暫存 {key} 型別錯誤")
    snapshot = review_snapshot.read_report_json(review_snapshot.report_dir(target) / review_snapshot.SNAPSHOT)
    staged = {"snapshot_git_revision": snapshot["git_revision"],
              "source_hashes": snapshot["source_hashes"],
              "payload": payload}
    from evidence_integrity import enabled as integrity_enabled
    if integrity_enabled(target):
        manifest = integrity_read(target / integrity_manifest)
        if not isinstance(manifest, dict):
            raise ValueError("尚未執行 --seal-integrity 建立可信審查起點")
        staged["integrity_head"] = manifest["head"]
    raw = json.dumps(staged, sort_keys=True, ensure_ascii=False)
    key = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]
    path = review_snapshot.report_dir(target) / review_snapshot.STAGED / f"{key}.json"
    _write(path, staged)
    return path.as_posix()


def _withdrawal_text(value: Any, minimum: int) -> bool:
    return isinstance(value, str) and len(value.strip()) >= minimum


def _counter_evidence_errors(target: Path, rid: str, evidence: Any,
                             source_hashes: dict[str, str]) -> list[str]:
    if not isinstance(evidence, list) or not evidence:
        return [f"{rid}: 撤回 fail 須附至少一筆實際來源反證"]
    errors = []
    for pos, item in enumerate(evidence):
        if (not isinstance(item, dict)
                or set(item) != {"path", "line_start", "line_end", "description"}):
            errors.append(f"{rid}: 反證[{pos}] 須且只能包含 path、line_start、line_end、description")
            continue
        path, start, end = item["path"], item["line_start"], item["line_end"]
        if not isinstance(path, str) or path not in source_hashes:
            errors.append(f"{rid}: 反證[{pos}] 的檔案不在來源快照")
            continue
        lines = len((target / path).read_bytes().splitlines())
        if (type(start) is not int or type(end) is not int
                or not 1 <= start <= end <= lines):
            errors.append(f"{rid}: 反證[{pos}] 的行號超出 {path} 實際範圍")
        if not _withdrawal_text(item["description"], 20):
            errors.append(f"{rid}: 反證[{pos}] 須具體說明此段程式碼如何推翻原判定")
    return errors


def _withdraw_fail_findings(target: Path, snapshot: dict, requests: dict[str, Any],
                            withdrawn_rules: set[str], checks_before: dict[str, dict],
                            checks: dict[str, dict], findings: dict[str, dict]) -> list[dict]:
    """已確認 fail 改判為非 fail 的唯一路徑：Finding 移出清單但保留全文、反證與雜湊。"""
    unused = sorted(set(requests) - withdrawn_rules)
    if unused:
        raise ValueError("fail_withdrawals 只能用於本批由已完成 fail 改判的規則：" + "、".join(unused))
    serialized = lambda obj: json.dumps(obj, ensure_ascii=False, sort_keys=True,
                                        separators=(",", ":")).encode("utf-8")
    errors: list[str] = []
    withdrawn_ids: dict[str, list[str]] = {}
    for rid in sorted(withdrawn_rules):
        request = requests[rid]
        if (not isinstance(request, dict) or set(request) != {
                "reason", "first_pass_error", "reviewer", "counter_evidence"}):
            errors.append(f"{rid}: fail_withdrawals 須且只能包含 reason、first_pass_error、reviewer、counter_evidence")
            continue
        if not _withdrawal_text(request["reason"], 40):
            errors.append(f"{rid}: 撤回理由須至少 40 字並描述實際重查")
        if not _withdrawal_text(request["first_pass_error"], 30):
            errors.append(f"{rid}: 須說明第一輪誤判的具體原因（至少 30 字）")
        if not _withdrawal_text(request["reviewer"], 4):
            errors.append(f"{rid}: 撤回須記錄覆核者")
        errors += _counter_evidence_errors(target, rid, request["counter_evidence"],
                                           snapshot["source_hashes"])
        ids = sorted(set(checks_before[rid].get("finding_ids") or []))
        for fid in ids:
            finding = findings.get(fid)
            if finding is None:
                errors.append(f"{rid}: 找不到要撤回的 Finding {fid}")
                continue
            remaining = sorted(set(finding.get("check_ids") or []) - withdrawn_rules)
            if remaining:
                errors.append(f"{fid}: Finding 仍關聯未撤回的規則 {'、'.join(remaining)}；"
                              "須一併撤回或維持 fail")
        if set(checks[rid].get("finding_ids") or []) & set(ids):
            errors.append(f"{rid}: 改判後的檢核不得再引用被撤回的 Finding")
        withdrawn_ids[rid] = ids
    if errors:
        raise ValueError("；".join(errors[:12]))
    records = []
    for rid in sorted(withdrawn_rules):
        request = requests[rid]
        removed = [findings[fid] for fid in withdrawn_ids[rid]]
        records.append({
            "rule_id": rid,
            "previous_status": "fail",
            "new_status": checks[rid]["status"],
            "previous_check_sha256": hashlib.sha256(serialized(checks_before[rid])).hexdigest(),
            "finding_ids": withdrawn_ids[rid],
            "withdrawn_findings": removed,
            "finding_sha256": {f["id"]: hashlib.sha256(serialized(f)).hexdigest() for f in removed},
            "reason": request["reason"].strip(),
            "first_pass_error": request["first_pass_error"].strip(),
            "counter_evidence": request["counter_evidence"],
            "reviewer": request["reviewer"].strip(),
            "recorded_on": date.today().isoformat(),
        })
    for ids in withdrawn_ids.values():
        for fid in ids:
            findings.pop(fid, None)
    return records


def integrate(target: Path, *, allow_revision: bool = False,
              allow_finding_revision: bool = False,
              allow_fail_withdrawal: bool = False) -> dict:
    if allow_finding_revision and not allow_revision:
        raise ValueError("Finding 修訂需要同時指定 --allow-revision")
    if allow_fail_withdrawal and not allow_revision:
        raise ValueError("撤回已確認 fail 需要同時指定 --allow-revision")
    failures = review_snapshot.snapshot_errors(target)
    from evidence_integrity import errors as evidence_integrity_errors
    failures += evidence_integrity_errors(target)
    if failures:
        raise ValueError("；".join(failures))
    folder = review_snapshot.report_dir(target) / review_snapshot.STAGED
    paths = sorted(folder.glob("*.json")) if folder.exists() else []
    if not paths:
        return {"applied": 0, "message": "沒有待整合的暫存資料"}
    boundary_attestation = None
    if os.environ.get("SECURITY_CODE_REVIEW_EXECUTION_MODE") == "optimized":
        from execution_boundary import require_clean
        batch_key = hashlib.sha256("|".join(p.name for p in paths).encode("utf-8")).hexdigest()[:24]
        boundary_attestation = require_clean(target, batch_id=batch_key, stage="first_pass")
    assessment_path = review_snapshot.report_dir(target) / "assessment.json"
    data = review_snapshot.read_report_json(assessment_path)
    if not isinstance(data, dict):
        raise ValueError("assessment.json 不存在或格式錯誤")
    snapshot = review_snapshot.read_report_json(review_snapshot.report_dir(target) / review_snapshot.SNAPSHOT)
    from evidence_integrity import enabled as integrity_enabled
    integrity_head = (integrity_read(target / integrity_manifest)["head"]
                      if integrity_enabled(target) else None)
    files = {r["path"]: r for r in data.get("file_reviews", [])}
    previous_assessment = json.loads(json.dumps(data, ensure_ascii=False))
    checks = {r["id"]: r for r in data.get("checks", [])}
    checks_before = {rid: json.loads(json.dumps(value, ensure_ascii=False))
                     for rid, value in checks.items()}
    findings = {r["id"]: r for r in data.get("findings", [])}
    amendment_history = list(data.get("finding_amendments") or [])
    withdrawal_history = list(data.get("fail_withdrawals") or [])
    staged_withdrawals: dict[str, Any] = {}
    withdrawn_rules: set[str] = set()
    amended_findings: set[str] = set()
    closures = review_snapshot.read_report_json(review_snapshot.report_dir(target) / review_snapshot.CLOSURES, {}) or {}
    control_verifications = review_snapshot.read_report_json(review_snapshot.report_dir(target) / review_snapshot.CONTROL_VERIFICATIONS, {}) or {}
    decision_audits = review_snapshot.read_report_json(review_snapshot.report_dir(target) / review_snapshot.DECISION_AUDITS, {}) or {}
    adversarial_reviews = review_snapshot.read_report_json(review_snapshot.report_dir(target) / review_snapshot.ADVERSARIAL_REVIEWS, {}) or {}
    # Keep pre-integration sidecars for delta validation of existing completed evidence.
    previous_closures = json.loads(json.dumps(closures, ensure_ascii=False))
    previous_verifications = json.loads(json.dumps(control_verifications, ensure_ascii=False))
    previous_audits = json.loads(json.dumps(decision_audits, ensure_ascii=False))
    known_fingerprints = {_fingerprint(f): fid for fid, f in findings.items()}
    new_files: set[str] = set()
    changed_file_evidence: set[str] = set()
    newly_completed_paths: set[str] = set()
    new_checks: set[str] = set()
    new_closures: set[str] = set()
    new_control_verifications: set[str] = set()
    new_decision_audits: set[str] = set()
    new_adversarial_reviews: set[str] = set()
    aliases: dict[str, str] = {}
    recheck = review_snapshot.read_report_json(review_snapshot.report_dir(target) / review_snapshot.RECHECK, {}) or {}
    required_recheck = set(recheck.get("rule_ids", []))
    newly_rechecked: set[str] = set()
    newly_rechecked_receipts: dict[str, dict] = {}

    # 先於記憶體完整調和、偵測衝突，絕不分批覆蓋正式檔。
    for path in paths:
        staged = review_snapshot.read_report_json(path)
        if integrity_head is not None and staged.get("integrity_head") != integrity_head:
            raise ValueError(f"{path.name}: 暫存基礎版本已被其他整合改變；請重新核對並暫存")
        if (staged.get("snapshot_git_revision") != snapshot["git_revision"]
                or staged.get("source_hashes") != snapshot["source_hashes"]):
            raise ValueError(f"{path.name}: 暫存使用不同的來源快照")
        part = staged["payload"]
        for rid, request in (part.get("fail_withdrawals") or {}).items():
            if rid in staged_withdrawals and staged_withdrawals[rid] != request:
                raise ValueError(f"{rid}: 多份暫存的 fail 撤回內容衝突，需人工裁決")
            staged_withdrawals[rid] = request
        for record in part.get("file_reviews", []):
            name = record["path"]
            if name not in snapshot["source_hashes"]:
                raise ValueError(f"{name}: 暫存檔不在來源快照")
            if name in files and files[name] != record:
                if name in new_files or not allow_revision:
                    raise ValueError(f"{name}: 逐檔結果衝突，須人工核對後才允許修訂")
            if files.get(name) != record:
                changed_file_evidence.add(name)
            files[name] = record
            new_files.add(name)
        revisions = part.get("finding_revisions") or {}
        if not isinstance(revisions, dict):
            raise ValueError("finding_revisions 必須為 Finding ID 對應的理由物件")
        changed_finding_ids = {item["id"] for item in part.get("findings", [])
                               if item["id"] in findings and findings[item["id"]] != item}
        if set(revisions) != changed_finding_ids:
            raise ValueError("Finding 修訂說明必須精確對應已變更的 Finding ID")
        for record in part.get("findings", []):
            fid = record["id"]
            fingerprint = _fingerprint(record)
            if fid in findings and findings[fid] != record:
                if not allow_finding_revision or fid in amended_findings:
                    raise ValueError(f"{fid}: Finding ID 衝突；須明確授權單筆修訂")
                old = findings[fid]
                revision = revisions.get(fid)
                if (not isinstance(revision, dict)
                        or set(revision) != {"reason", "reviewer"}
                        or not isinstance(revision.get("reason"), str)
                        or len(revision["reason"].strip()) < 40
                        or not isinstance(revision.get("reviewer"), str)
                        or len(revision["reviewer"].strip()) < 4):
                    raise ValueError(f"{fid}: 修訂必須具備具體 40 字理由及人工覆核者")
                if (old.get("confidence") == "confirmed"
                        and record.get("confidence") != "confirmed"):
                    raise ValueError(f"{fid}: 不得降低已確認 Finding 的證據信心")
                if not set(old.get("check_ids", [])).issubset(record.get("check_ids", [])):
                    raise ValueError(f"{fid}: 不得解除 Finding 既有規則關聯")
                # 舊紀錄的 critical 已併入 high，改為 high 不算降級。
                levels = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 3}
                if levels.get(record.get("severity"), -1) < levels.get(old.get("severity"), -1):
                    raise ValueError(f"{fid}: 不得在一般修訂中降低既有 Finding 嚴重度")
                if not record.get("evidence"):
                    raise ValueError(f"{fid}: 修訂不得清空既有弱點證據")
                serialized = lambda obj: json.dumps(obj, ensure_ascii=False, sort_keys=True,
                                                    separators=(",", ":")).encode("utf-8")
                amendment_history.append({
                    "finding_id": fid,
                    "previous_sha256": hashlib.sha256(serialized(old)).hexdigest(),
                    "updated_sha256": hashlib.sha256(serialized(record)).hexdigest(),
                    "previous_finding": old,
                    "reason": revision["reason"].strip(),
                    "reviewer": revision["reviewer"].strip(),
                    "recorded_on": date.today().isoformat(),
                })
                amended_findings.add(fid)
                old_fp = _fingerprint(old)
                if known_fingerprints.get(old_fp) == fid:
                    del known_fingerprints[old_fp]
            if fingerprint in known_fingerprints and known_fingerprints[fingerprint] != fid:
                canonical = findings[known_fingerprints[fingerprint]]
                # 同位置／標題不代表證據、影響與建議相同；不得靜默遺失詳情。
                if ({k: v for k, v in canonical.items() if k != "id"} !=
                        {k: v for k, v in record.items() if k != "id"}):
                    raise ValueError(f"{fid}: Finding 疑似重複但內容不同，須人工整併證據")
                aliases[fid] = known_fingerprints[fingerprint]
                continue
            findings[fid] = record
            known_fingerprints[fingerprint] = fid
        for record in part.get("checks", []):
            rid = record["id"]
            if rid not in checks:
                raise ValueError(f"{rid}: 不存在的 70 項檢核 ID")
            record = dict(record)
            if "finding_ids" in record:
                record["finding_ids"] = sorted(set(aliases.get(x, x) for x in record["finding_ids"]))
            if rid in new_checks and checks[rid] != record:
                raise ValueError(f"{rid}: 多份暫存規則結果衝突，需人工裁決")
            if checks[rid] != record and (checks[rid].get("execution") or {}).get("state") == "completed":
                if checks[rid].get("status") == "fail" and record.get("status") != "fail":
                    if not allow_fail_withdrawal or rid not in staged_withdrawals:
                        raise ValueError(f"{rid}: 不允許未裁決即將已確認弱點改判為非 fail；"
                                         "須在 fail_withdrawals 提出反證並明確授權 --allow-fail-withdrawal")
                    withdrawn_rules.add(rid)
                if not allow_revision:
                    raise ValueError(f"{rid}: 已完成的規則不同，須明確人工允許修訂")
            if ((checks[rid].get("execution") or {}).get("state") != "completed"
                    and (record.get("execution") or {}).get("state") == "completed"):
                newly_completed_paths.update((record.get("execution") or {}).get("inspected_paths") or [])
            checks[rid] = record
            new_checks.add(rid)
            if rid in required_recheck and (record.get("execution") or {}).get("state") == "completed":
                if not record.get("evidence") or not (record.get("execution") or {}).get("methods"):
                    raise ValueError(f"{rid}: 來源異動後重新完成須附實際分析證據及方法")
                if recheck.get("schema_version") == 2:
                    # Replayed completed checks cannot clear a new version obligation.
                    proof = (part.get("recheck_proof") or {}).get(rid)
                    changed_paths = recheck.get("changed_source_paths") or []
                    expected = {p: snapshot["source_hashes"][p] for p in changed_paths
                                if p in snapshot["source_hashes"]}
                    removed_paths = sorted(p for p in changed_paths
                                           if p not in snapshot["source_hashes"])
                    if (checks_before.get(rid) == record
                            or not isinstance(proof, dict)
                            or proof.get("snapshot_fingerprint") != snapshot_fingerprint(snapshot)
                            or proof.get("source_hashes") != expected
                            or proof.get("removed_source_paths", []) != removed_paths
                            or not isinstance(proof.get("verification_summary"), str)
                            or len(proof["verification_summary"].strip()) < 40):
                        raise ValueError(f"{rid}: 重新查核須新增實際證據，並提供綁定當前來源快照的查核紀錄")
                    receipt_hash = hashlib.sha256(json.dumps(
                        proof, ensure_ascii=False, sort_keys=True,
                        separators=(",", ":")).encode("utf-8")).hexdigest()
                    newly_rechecked_receipts[rid] = {
                        "snapshot_fingerprint": proof["snapshot_fingerprint"],
                        "receipt_sha256": receipt_hash,
                    }
                newly_rechecked.add(rid)
        for rid, record in part.get("closures", {}).items():
            if rid not in review_snapshot.rule_scopes():
                raise ValueError(f"{rid}: 結案包含未知規則")
            if rid in closures and closures[rid] != record and (rid in new_closures or not allow_revision):
                raise ValueError(f"{rid}: 跨檔結案紀錄衝突，須人工核對")
            closures[rid] = record
            new_closures.add(rid)
        for rid, record in part.get("control_verifications", {}).items():
            if rid not in checks:
                raise ValueError(f"{rid}: P2 控制有效性包含未知規則")
            if not isinstance(record, dict):
                raise ValueError(f"{rid}: P2 控制有效性紀錄必須為物件")
            if (rid in control_verifications and control_verifications[rid] != record
                    and (rid in new_control_verifications or not allow_revision)):
                raise ValueError(f"{rid}: P2 控制有效性紀錄衝突，須人工核對或明確允許修訂")
            control_verifications[rid] = record
            new_control_verifications.add(rid)
        for rid, record in part.get("decision_audits", {}).items():
            if rid not in checks:
                raise ValueError(f"{rid}: P3 判定紀錄包含未知規則")
            if not isinstance(record, dict):
                raise ValueError(f"{rid}: P3 判定紀錄必須為物件")
            if (rid in decision_audits and decision_audits[rid] != record
                    and (rid in new_decision_audits or not allow_revision)):
                raise ValueError(f"{rid}: P3 判定紀錄衝突，須人工核對或明確允許修訂")
            decision_audits[rid] = record
            new_decision_audits.add(rid)
        for rid, record in part.get("adversarial_reviews", {}).items():
            if rid not in checks:
                raise ValueError(f"{rid}: 第二輪複核包含未知規則")
            from adversarial_recheck import BASELINE, digest
            baseline = review_snapshot.read_report_json(target / BASELINE, {})
            original = (baseline.get("checks") or {}).get(rid) if isinstance(baseline, dict) else None
            if not isinstance(original, dict):
                raise ValueError(f"{rid}: 尚未執行 --begin-second-pass 固定第一輪判定")
            if (checks[rid].get("execution") or {}).get("state") != "completed":
                raise ValueError(f"{rid}: 第一輪檢核尚未完成，不得儲存第二輪結論")
            if not isinstance(record, dict) or record.get("baseline_digest") != original["digest"]:
                raise ValueError(f"{rid}: 第二輪紀錄未對應不可變的第一輪判定指紋")
            if record.get("final_digest") != digest(checks[rid]):
                raise ValueError(f"{rid}: 第二輪紀錄必須對應整合後的正式判定")
            if (rid in adversarial_reviews and adversarial_reviews[rid] != record
                    and (rid in new_adversarial_reviews or not allow_revision)):
                raise ValueError(f"{rid}: 第二輪複核紀錄衝突，須人工核對或明確允許修訂")
            adversarial_reviews[rid] = record
            new_adversarial_reviews.add(rid)
        # 獨立抽樣併入既有受控 adversarial-reviews.json；
        # 不新增 Manifest TRACKED 欄位，保留舊交易鏈的相容性。
        sample_entries = part.get("second_pass_samples", {})
        if sample_entries:
            from second_pass_layers import RESERVED, record_errors
            layer = adversarial_reviews.get(RESERVED)
            if not isinstance(layer, dict) or not isinstance(layer.get("plan"), dict):
                raise ValueError("第二輪抽樣：缺少已封存的分層計畫")
            samples = dict(layer.get("samples", {}))
            source_snapshot = review_snapshot.read_report_json(review_snapshot.report_dir(target) / review_snapshot.SNAPSHOT, {})
            sample_assessment = {"findings": list(findings.values()), "checks": list(checks.values())}
            for source_path, sample in sample_entries.items():
                problems = record_errors(target, source_path, sample, layer["plan"],
                                         source_snapshot, sample_assessment)
                if problems:
                    raise ValueError("；".join(problems))
                if source_path in samples and samples[source_path] != sample and not allow_revision:
                    raise ValueError(f"第二輪抽樣：{source_path} 紀錄衝突，需人工允許修訂")
                samples[source_path] = sample
            adversarial_reviews[RESERVED] = {**layer, "samples": samples}

    if staged_withdrawals:
        withdrawal_history += _withdraw_fail_findings(
            target, snapshot, staged_withdrawals, withdrawn_rules,
            checks_before, checks, findings)
    # 不允許因去重而留下錯誤 Finding ID 參照。
    for check in checks.values():
        for fid in check.get("finding_ids", []):
            if fid not in findings:
                raise ValueError(f"{check['id']}: 找不到 Finding {fid}")
    for record in findings.values():
        for rid in record.get("check_ids", []):
            if rid not in checks:
                raise ValueError(f"Finding 關聯未知規則 {rid}")
    data["file_reviews"] = [files[p] for p in sorted(files)]
    data["checks"] = [checks[r["id"]] for r in data["checks"]]
    data["findings"] = [findings[p] for p in sorted(findings)]
    if amendment_history:
        data["finding_amendments"] = amendment_history
    if withdrawal_history:
        data["fail_withdrawals"] = withdrawal_history
    # 批次品質及新增檔案關聯必須在任何正式寫入／Journal 交易前通過。
    # 不對舊批次未更動的錯誤直接改判，也不得藉 allow_revision 繞過。
    defects = batch_quality_errors(
        target, previous_assessment, data,
        changed_paths=changed_file_evidence | newly_completed_paths,
        snapshot_paths=set(snapshot["source_hashes"]),
    )
    if defects:
        raise ValueError("；".join(defects[:12]))
    # Validate newly completed rules against the merged assessment and sidecars,
    # not the old on-disk evidence. Incremental repairs must not regress existing
    # completed rules; unrelated historical gaps remain subject to full validation.
    from batch_evidence_gate import completion_transition_errors
    defects = completion_transition_errors(
        target, previous_assessment, data,
        before_closures=previous_closures, after_closures=closures,
        before_verifications=previous_verifications, after_verifications=control_verifications,
        before_audits=previous_audits, after_audits=decision_audits,
    )
    if defects:
        raise ValueError("；".join(defects[:12]))
    # 跨多檔交易預寫入可核對的 ahead-log；中斷後須人工呼叫復原。
    if integrity_enabled(target):
        from evidence_integrity import commit as integrity_commit
        updates = {
            "assessment.json": data,
            "analysis/rule-closures.json": closures,
            "analysis/control-verifications.json": control_verifications,
            "analysis/decision-audits.json": decision_audits,
            "analysis/adversarial-reviews.json": adversarial_reviews,
        }
        if required_recheck:
            recheck["rule_ids"] = sorted(required_recheck - newly_rechecked)
            if newly_rechecked_receipts:
                recheck["verified_rechecks"] = {
                    **(recheck.get("verified_rechecks") or {}),
                    **newly_rechecked_receipts,
                }
            updates["analysis/recheck-required.json"] = recheck
        integrity_commit(target, updates, event="integrate", staged_paths=paths,
                         boundary_attestation=boundary_attestation)
    else:
        _write(review_snapshot.report_dir(target) / review_snapshot.CLOSURES, closures)
        _write(review_snapshot.report_dir(target) / review_snapshot.CONTROL_VERIFICATIONS, control_verifications)
        _write(review_snapshot.report_dir(target) / review_snapshot.DECISION_AUDITS, decision_audits)
        _write(review_snapshot.report_dir(target) / review_snapshot.ADVERSARIAL_REVIEWS, adversarial_reviews)
        _write(assessment_path, data)
        if required_recheck:
            recheck["rule_ids"] = sorted(required_recheck - newly_rechecked)
            if newly_rechecked_receipts:
                recheck["verified_rechecks"] = {
                    **(recheck.get("verified_rechecks") or {}),
                    **newly_rechecked_receipts,
                }
            _write(review_snapshot.report_dir(target) / review_snapshot.RECHECK, recheck)
        for path in paths:
            path.unlink()
    return {"applied": len(paths), "files": len(new_files),
            "checks": len(new_checks), "findings": len(findings), "closures": len(new_closures),
            "control_verifications": len(new_control_verifications),
            "decision_audits": len(new_decision_audits),
            "adversarial_reviews": len(new_adversarial_reviews)}


def refresh_snapshot(target: Path) -> None:
    folder = review_snapshot.report_dir(target) / review_snapshot.STAGED
    if folder.is_dir() and any(folder.glob("*.json")):
        raise ValueError("尚有未整合暫存；禁止刷新來源快照")
    from evidence_integrity import enabled as integrity_enabled, errors as integrity_errors
    active = integrity_enabled(target) and (
        (target / integrity_manifest).exists()
        or (review_snapshot.report_dir(target) / "assessment.json").exists())
    if active:
        problems = integrity_errors(target)
        if problems:
            raise ValueError("；".join(problems))
    old = review_snapshot.read_report_json(review_snapshot.report_dir(target) / review_snapshot.SNAPSHOT)
    if not isinstance(old, dict) or not isinstance(old.get("source_hashes"), dict):
        raise ValueError("尚未建立有效審查快照")
    assessment = review_snapshot.read_report_json(review_snapshot.report_dir(target) / "assessment.json", {}) or {}
    excludes = sorted({str(row.get("path", "")) for row in
                       (assessment.get("scope_details") or {}).get("excluded_paths", [])
                       if isinstance(row, dict)})
    if excludes != old.get("excluded_paths", []):
        raise ValueError("審查排除範圍已改變；須完整重新盤點，禁止增量套用舊結論")
    current = review_snapshot.current_hashes(target, excludes)
    updated_snapshot = {"schema_version": 1, "git_revision": review_snapshot.git_revision(target),
                        "source_hashes": current, "excluded_paths": excludes}
    if old == updated_snapshot:
        return

    delta = source_delta(old["source_hashes"], current)
    changed_paths = sorted(set().union(*map(set, delta.values())))
    updates: dict[str, Any] = {"analysis/review-snapshot.json": updated_snapshot}
    if changed_paths:
        index = review_snapshot.read_report_json(review_snapshot.report_dir(target) / review_snapshot.INDEX, {}) or {}
        closures = review_snapshot.read_report_json(review_snapshot.report_dir(target) / review_snapshot.CLOSURES, {}) or {}
        # Also consider newly introduced control patterns in modified sources.
        # Parser failures force the conservative full-rule fallback.
        current_candidates = {}
        try:
            from analysis_candidates import candidate_hits
            from source_reader import read_source_text
            for source_path in delta["modified"]:
                if source_path.lower().endswith(".cs"):
                    current_candidates[source_path] = candidate_hits(
                        source_path, read_source_text(target / source_path)[0])
        except (OSError, UnicodeError, ValueError, TypeError):
            current_candidates = {}
        impact = affected_rules(old["source_hashes"], current, index,
                                assessment, closures, review_snapshot.rule_scopes(),
                                current_candidates=current_candidates)
        previous = review_snapshot.read_report_json(review_snapshot.report_dir(target) / review_snapshot.RECHECK, {}) or {}
        recheck = {
            "schema_version": 2,
            "rule_ids": sorted(set(previous.get("rule_ids") or []) | set(impact["rule_ids"])),
            "reason": "來源變更；需對影響閉包重新取得實際證據",
            "source_delta": delta,
            "changed_source_paths": sorted(set(previous.get("changed_source_paths") or [])
                                           | set(changed_paths)),
            "impact_reason": impact["reason"],
            "full_recheck": impact["full_recheck"],
        }
        # Only invalidate affected closures. The formal verifier still checks
        # retained relationships against the regenerated source index.
        retained = {rid: record for rid, record in closures.items()
                    if rid not in impact["rule_ids"]}
        updates.update({
            "analysis/recheck-required.json": recheck,
            "analysis/rule-closures.json": retained,
        })
    # Sidecar proofs also bind their snapshot_fingerprint to Git Revision.
    # Reanchor only records already bound to the previous trusted snapshot.
    # An active second-pass baseline cannot be reanchored without restarting
    # its challenge/sample plan, so fail closed rather than silently rewriting.
    if not changed_paths:
        baseline_path = review_snapshot.report_dir(target) / "analysis/first-pass-baseline.json"
        if baseline_path.is_file():
            raise ValueError("第二輪 baseline 已建立；不可僅更新 Git 錨點，"
                             "須先確認來源版本並使用正式第二輪重啟流程")
        old_fp = snapshot_fingerprint(old)
        new_fp = snapshot_fingerprint(updated_snapshot)
        for sidecar in (review_snapshot.CONTROL_VERIFICATIONS, review_snapshot.DECISION_AUDITS):
            records = review_snapshot.read_report_json(review_snapshot.report_dir(target) / sidecar)
            if records is None:
                continue
            if not isinstance(records, dict):
                raise ValueError(f"{sidecar}: 原始佐證格式無效，禁止自動重新錨定")
            updated_records = {}
            for rid, record in records.items():
                if not isinstance(record, dict):
                    updated_records[rid] = record
                    continue
                if (record.get("git_revision") == old["git_revision"]
                        and record.get("snapshot_fingerprint") == old_fp):
                    revised = dict(record)
                    revised["git_revision"] = updated_snapshot["git_revision"]
                    revised["snapshot_fingerprint"] = new_fp
                    updated_records[rid] = revised
                else:
                    # Do not launder a stale/invalid preexisting evidence record.
                    updated_records[rid] = record
            if updated_records != records:
                updates[sidecar.as_posix()] = updated_records
    if active:
        from evidence_integrity import commit as integrity_commit
        integrity_commit(target, updates, event="snapshot-refresh",
                         new_snapshot=updated_snapshot)
    else:
        for path, payload in updates.items():
            _write(review_snapshot.report_dir(target) / path, payload)


def main() -> int:
    parser = argparse.ArgumentParser(description="單代理審查完整性守門；不修改受測原始碼")
    parser.add_argument("--target", type=Path, default=Path.cwd())
    parser.add_argument("--plan", action="store_true")
    parser.add_argument("--seal-integrity", action="store_true",
                        help="核對既有資料後，明確建立第一筆完整性封存")
    parser.add_argument("--recover-integrity", action="store_true",
                        help="核對 SHA256 後重播中斷的多檔整合交易")
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--stage", type=Path, help="暫存單檔或單批審查 JSON，不能直接寫正式結果")
    parser.add_argument("--integrate", action="store_true")
    parser.add_argument("--allow-revision", action="store_true",
                        help="人工核對後允許覆核既有 completed；仍禁止抹除已確認 fail")
    parser.add_argument("--allow-finding-revision", action="store_true",
                        help="搭配 --integrate --allow-revision 與 finding_revisions 明確修訂既有 Finding")
    parser.add_argument("--allow-fail-withdrawal", action="store_true",
                        help="搭配 --integrate --allow-revision 與 fail_withdrawals，以反證撤回誤判的已確認 fail")
    parser.add_argument("--restart-second-pass", action="store_true",
                        help="明確重新執行第一輪後，歸檔舊快照／複核紀錄並重啟第二輪")
    parser.add_argument("--begin-second-pass", action="store_true",
                        help="第一輪 70 項完成後，固定不可變結果並開始反向複核")
    parser.add_argument("--snapshot-refresh", action="store_true",
                        help="明確更新來源版本，清除過期結案；所有受影響規則須重審")
    args = parser.parse_args()
    if args.allow_finding_revision and (not args.integrate or not args.allow_revision):
        parser.error("--allow-finding-revision 須搭配 --integrate --allow-revision")
    if args.allow_fail_withdrawal and (not args.integrate or not args.allow_revision):
        parser.error("--allow-fail-withdrawal 須搭配 --integrate --allow-revision")
    try:
        if args.recover_integrity:
            from evidence_integrity import recover
            print(json.dumps(recover(args.target), ensure_ascii=False))
        elif args.seal_integrity:
            from evidence_integrity import initialize as seal
            # 明確遷移既有檢核結果前，必須先確定來源／Git 與分析索引一致。
            problems = review_snapshot.snapshot_errors(args.target)
            if problems:
                raise ValueError("；".join(problems))
            print(json.dumps(seal(args.target, explicit=True), ensure_ascii=False))
        elif args.begin_second_pass or args.restart_second_pass:
            from adversarial_recheck import begin_second_pass
            data = review_snapshot.read_report_json(review_snapshot.report_dir(args.target) / "assessment.json", {}) or {}
            print(json.dumps(begin_second_pass(args.target, data, restart=args.restart_second_pass),
                             ensure_ascii=False))
        elif args.snapshot_refresh:
            refresh_snapshot(args.target)
            print("PASS: snapshot refreshed; previous conclusions require recheck")
        elif args.stage:
            print("STAGED:", stage(args.target, args.stage))
        elif args.integrate:
            print(json.dumps(integrate(args.target, allow_revision=args.allow_revision,
                                       allow_finding_revision=args.allow_finding_revision,
                                       allow_fail_withdrawal=args.allow_fail_withdrawal), ensure_ascii=False))
        elif args.plan:
            print(json.dumps(review_snapshot.scope_tasks(args.target), ensure_ascii=False, indent=2))
        elif args.validate:
            errors = safety_errors(args.target, review_snapshot.read_report_json(review_snapshot.report_dir(args.target) / "assessment.json", {}) or {})
            for error in errors:
                print("ERROR:", error, file=sys.stderr)
            if errors:
                return 1
            print("PASS: review safeguards verified")
        else:
            parser.error("請指定 --plan、--validate、--stage、--integrate、--seal-integrity、--recover-integrity、--begin-second-pass、--restart-second-pass 或 --snapshot-refresh")
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    from review_log import logged_main
    phase = ("second_pass" if "--begin-second-pass" in sys.argv or "--restart-second-pass" in sys.argv
             else "first_pass" if "--stage" in sys.argv or "--integrate" in sys.argv
             else "validation")
    raise SystemExit(logged_main(main, phase))
