#!/usr/bin/env python3
"""單代理第二輪反向複核：固定第一輪結果，核對真實反例及矛盾裁決。"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from control_effectiveness import snapshot_fingerprint, _location_errors
from review_decision import _is_weak_source_evidence, load_decision_matrix

CONTRACT_VERSION = 1
RELATIVE = Path("reports/security-code-review/analysis")
INDEX = RELATIVE / "structure-index.json"
SNAPSHOT = RELATIVE / "review-snapshot.json"
BASELINE = RELATIVE / "first-pass-baseline.json"
REVIEWS = RELATIVE / "adversarial-reviews.json"
HIGH_RISK_RULES = frozenset({
    "AC-01", "AC-02", "AC-04", "AC-06", "AC-08",
    "AU-03", "AU-06", "AU-08", "AU-09",
    "IN-01", "IN-02", "IN-03", "IN-04", "IN-06", "IN-07", "IN-08",
    "CR-01", "CR-02", "CR-03", "CR-05", "CR-06", "PD-02", "PD-06",
})


def _read(path: Path, default: Any = None) -> Any:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else default


def digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=False,
                         separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def guidance(rule_id: str) -> dict[str, Any]:
    matrix = load_decision_matrix()
    if rule_id not in matrix:
        raise ValueError(f"未知規則：{rule_id}")
    return {
        "phase": "adversarial_second_pass",
        "single_agent": True,
        "truly_independent": False,
        "required_hypotheses": 2 if rule_id in HIGH_RISK_RULES else 1,
        "hypothesis_focus": (
            ["alternative_entry", "bypass_or_counterexample"] if rule_id in HIGH_RISK_RULES
            else ["counterexample_or_opposite_verdict"]
        ),
        "method": "重新閱讀來源，從攻擊者觀點尋找另一入口／不安全分支／相反判定",
        "evidence_contract": "第一輪固定摘要、反例來源、修訂後結論、矛盾裁決與未結問題",
        "cannot_skip": "任何已完成規則，包括 pass/fail/review/na，均需第二輪複核",
    }


def _enabled(target: Path) -> bool:
    index = _read(target / INDEX, {})
    return isinstance(index, dict) and index.get("adversarial_second_pass_version") == CONTRACT_VERSION


def begin_second_pass(target: Path, assessment: dict[str, Any]) -> dict[str, Any]:
    """在第一輪完整結案後才建立不可默默覆寫的版本錨點，不產生任何安全結論。"""
    target = target.resolve()
    if not _enabled(target):
        raise ValueError("索引未啟用第二輪複核，請先執行 analysis_prepare.py")
    checks = assessment.get("checks")
    matrix = load_decision_matrix()
    if (not isinstance(checks, list) or len(checks) != 70
            or {c.get("id") for c in checks if isinstance(c, dict)} != set(matrix)
            or any((c.get("execution") or {}).get("state") != "completed"
                   for c in checks if isinstance(c, dict))):
        raise ValueError("須先完成全部 70 項第一輪檢核，才能固定第二輪起點")
    from review_completion import completion_errors
    from review_decision import decision_quality_errors
    from review_safety import snapshot_errors, closure_errors
    from control_effectiveness import verification_errors
    from decision_adjudication import adjudication_errors
    from source_coverage import build_source_coverage

    issues = (snapshot_errors(target)
              + completion_errors(checks)
              + decision_quality_errors(checks, source_root=target)
              + closure_errors(target, assessment)
              + verification_errors(target, checks)
              + adjudication_errors(target, checks))
    coverage = build_source_coverage(assessment, target)
    issues += coverage.get("review_integrity_errors", [])
    if coverage["missing_source_file_count"]:
        issues.append("逐檔覆蓋尚未完成，禁止啟動第二輪")
    if issues:
        raise ValueError("第一輪審查或來源證據尚未完整：" + "；".join(issues[:8]))
    snap = _read(target / SNAPSHOT, {})
    if not isinstance(snap, dict) or not isinstance(snap.get("source_hashes"), dict):
        raise ValueError("沒有可使用的來源快照")
    checkpoint = {
        "schema_version": CONTRACT_VERSION,
        "snapshot_fingerprint": snapshot_fingerprint(snap),
        "checks": {c["id"]: {"status": c["status"], "digest": digest(c)}
                   for c in sorted(checks, key=lambda x: x["id"])},
    }
    path = target / BASELINE
    existing = _read(path)
    if existing is not None and existing != checkpoint:
        raise ValueError("已存在不同的第一輪快照，禁止自動覆寫；須釐清先前複核進度")
    if existing is None:
        from review_safety import _write
        _write(path, checkpoint)
    return {"rule_count": 70, "snapshot_fingerprint": checkpoint["snapshot_fingerprint"],
            "already_existed": existing is not None}


def _evidence_errors(target: Path, proof: Any, rid: str, label: str,
                     inspected: set[str], known: set[str], status: str,
                     audit: dict | None, formal_evidence: list[dict]) -> list[str]:
    if not isinstance(proof, dict):
        return [f"{rid}: {label} 缺少具體來源證據"]
    kind = proof.get("kind")
    if kind == "source":
        issues, _ = _location_errors(target, known, inspected, proof, f"{rid}: {label}")
        if issues:
            return issues
        if _is_weak_source_evidence(proof, target) is True:
            return [f"{rid}: {label} 只有宣告、using 或註解，不能證明反例"]
        return []
    if kind == "external_gap" and status == "review":
        gap = (audit or {}).get("external_gap")
        artifact = gap.get("artifact") if isinstance(gap, dict) else None
        if not isinstance(artifact, str) or proof.get("artifact") != artifact:
            return [f"{rid}: {label} 外部缺口須對應正式判定的具體待確認工件"]
        return []
    if kind == "external_artifact":
        reference = proof.get("artifact_id")
        if (not isinstance(reference, str) or not reference.strip()
                or not any(isinstance(item, dict) and item.get("artifact_id") == reference
                           and item.get("kind") in {"deployment", "operating_record", "policy",
                                                    "scan", "test", "interview"}
                           for item in formal_evidence)):
            return [f"{rid}: {label} 外部工件必須引用正式檢核中已存在的工件識別碼"]
        return []
    return [f"{rid}: {label} 缺少有效 source / external_gap / external_artifact 證據"]


def second_pass_errors(target: Path, assessment: dict[str, Any]) -> list[str]:
    """僅驗證工作紀錄及來源一致性；同一代理無法做到真正獨立的盲審。"""
    if not _enabled(target):
        return []
    checks = assessment.get("checks", [])
    if not isinstance(checks, list):
        return ["第二輪：assessment.checks 格式無效"]
    if not checks or any((c.get("execution") or {}).get("state") != "completed"
                         for c in checks if isinstance(c, dict)):
        return []  # 第一輪尚未完成時，保持原有 pending/blocked 工作狀態。
    baseline = _read(target / BASELINE)
    if not isinstance(baseline, dict) or baseline.get("schema_version") != CONTRACT_VERSION:
        return ["第二輪：尚未執行 review_safety.py --begin-second-pass 固定第一輪結果"]
    snapshot = _read(target / SNAPSHOT, {})
    if not isinstance(snapshot, dict) or baseline.get("snapshot_fingerprint") != snapshot_fingerprint(snapshot):
        return ["第二輪：第一輪快照與目前來源不同，禁止沿用舊複核結論"]
    original = baseline.get("checks")
    if not isinstance(original, dict) or set(original) != {c["id"] for c in checks}:
        return ["第二輪：第一輪結論 ID 與目前 70 項不一致"]
    stored = _read(target / REVIEWS, {})
    if not isinstance(stored, dict):
        return ["第二輪：adversarial-reviews.json 應為規則 ID 對應的物件"]
    known = set((snapshot.get("source_hashes") or {}).keys())
    existing_findings = {f.get("id") for f in assessment.get("findings", [])
                         if isinstance(f, dict)}
    decision_audits = _read(target / RELATIVE / "decision-audits.json", {})
    if not isinstance(decision_audits, dict):
        decision_audits = {}
    errors: list[str] = []
    for check in checks:
        rid, status = check.get("id"), check.get("status")
        first = original.get(rid)
        record = stored.get(rid)
        if not isinstance(record, dict):
            errors.append(f"{rid}: 第二輪反向複核缺少紀錄，須重新閱讀來源及攻擊路徑")
            continue
        if record.get("baseline_digest") != first.get("digest"):
            errors.append(f"{rid}: 第二輪原始判定指紋與第一輪快照不一致")
        current_digest = digest(check)
        altered = current_digest != first["digest"]
        if record.get("final_digest") != current_digest or record.get("final_status") != status:
            errors.append(f"{rid}: 第二輪結論與目前正式檢核不同，禁止套用舊核對紀錄")
        if record.get("snapshot_fingerprint") != baseline["snapshot_fingerprint"]:
            errors.append(f"{rid}: 第二輪來源快照已變更")
        outcome = record.get("outcome")
        if outcome != ("corrected" if altered else "confirmed"):
            errors.append(f"{rid}: 第一輪結論有異動時須列出矛盾與修訂，未異動須記 confirmed")
        if first["status"] == "fail" and status != "fail":
            errors.append(f"{rid}: 已確認弱點不得在第二輪被靜默降級")
        if not isinstance(record.get("attacker_perspective"), str) or len(
                record["attacker_perspective"].strip()) < 24:
            errors.append(f"{rid}: 缺少具體攻擊者觀點，不能沿用第一輪摘要")
        if not isinstance(record.get("search_summary"), str) or len(
                record["search_summary"].strip()) < 24:
            errors.append(f"{rid}: 缺少反向搜尋的實際入口、呼叫路徑及結果")
        if not isinstance(record.get("open_issues"), list) or record["open_issues"]:
            errors.append(f"{rid}: 第二輪仍有未完成或未裁決問題，不得交付")
        inspected = (check.get("execution") or {}).get("inspected_paths", [])
        if not isinstance(inspected, list):
            inspected = []
        inspected_set = set(p for p in inspected if isinstance(p, str))
        hypotheses = record.get("hypotheses")
        minimum = guidance(rid)["required_hypotheses"]
        if not isinstance(hypotheses, list) or len(hypotheses) < minimum:
            errors.append(f"{rid}: 第二輪至少需要 {minimum} 個具體反例假設")
            hypotheses = []
        seen: set[str] = set()
        results: list[str] = []
        for n, hypothesis in enumerate(hypotheses):
            label = f"反例[{n}]"
            if not isinstance(hypothesis, dict):
                errors.append(f"{rid}: {label} 必須為物件")
                continue
            surface = hypothesis.get("attack_surface")
            explanation = hypothesis.get("attempt")
            result = hypothesis.get("result")
            if not isinstance(surface, str) or not surface.strip() or surface in seen:
                errors.append(f"{rid}: {label} 攻擊面缺少名稱或與其他反例重複")
            else:
                seen.add(surface)
            if not isinstance(explanation, str) or len(explanation.strip()) < 24:
                errors.append(f"{rid}: {label} 需要記錄具體的反例追查方法")
            if result not in {"blocked", "confirmed_vulnerability", "external_boundary", "not_applicable"}:
                errors.append(f"{rid}: {label} 必須標記實際追查結果")
            else:
                results.append(result)
            errors += _evidence_errors(target, hypothesis.get("evidence"), rid,
                                       label, inspected_set, known, status,
                                       decision_audits.get(rid), check.get("evidence") or [])
        if (status == "pass" and any(x not in {"blocked", "not_applicable"} for x in results)
                or status == "fail" and "confirmed_vulnerability" not in results
                or status == "review" and "external_boundary" not in results
                or status == "na" and any(x != "not_applicable" for x in results)):
            errors.append(f"{rid}: 第二輪反例結果與正式 {status} 判定矛盾")
        if status == "fail":
            check_ids = set(check.get("finding_ids") or [])
            if not check_ids or not check_ids.issubset(existing_findings):
                errors.append(f"{rid}: 第二輪確認弱點但缺少實際存在的 Finding")
        contradictions = record.get("contradictions")
        if not isinstance(contradictions, list):
            errors.append(f"{rid}: 第二輪須明列 contradictions（無則 []）")
            contradictions = []
        if altered and not contradictions:
            errors.append(f"{rid}: 第一輪判定已改動，必須有矛盾發現及具體裁決證據")
        if not altered and contradictions:
            errors.append(f"{rid}: 未修訂原始判定卻宣稱已裁決矛盾")
        for i, contradiction in enumerate(contradictions):
            if not isinstance(contradiction, dict):
                errors.append(f"{rid}: 矛盾[{i}] 必須有完整裁決紀錄")
                continue
            if (contradiction.get("initial_status") != first["status"] or
                    contradiction.get("final_status") != status):
                errors.append(f"{rid}: 矛盾[{i}] 狀態與第一輪或修訂後判定不同")
            note = contradiction.get("resolution")
            if not isinstance(note, str) or len(note.strip()) < 30:
                errors.append(f"{rid}: 矛盾[{i}] 缺少具體裁決原因")
            errors += _evidence_errors(target, contradiction.get("evidence"), rid,
                                       f"矛盾[{i}]", inspected_set, known, status,
                                       decision_audits.get(rid), check.get("evidence") or [])
    return errors


def progress(target: Path, assessment: dict[str, Any], batch_size: int = 10) -> dict[str, Any]:
    checks = assessment.get("checks") or []
    if not _enabled(target):
        return {"enabled": False, "pending_ids": [], "completed": 0}
    base = _read(target / BASELINE)
    reviews = _read(target / REVIEWS, {})
    if not isinstance(reviews, dict):
        reviews = {}
    if not isinstance(base, dict):
        return {"enabled": True, "baseline_ready": False, "completed": 0,
                "pending_ids": [c["id"] for c in checks if isinstance(c, dict)][:batch_size],
                "pending_count": len(checks)}
    originals = base.get("checks") or {}
    pending = [c["id"] for c in checks if isinstance(c, dict)
               and (not isinstance(reviews.get(c["id"]), dict)
                    or reviews[c["id"]].get("final_digest") != digest(c))]
    return {"enabled": True, "baseline_ready": True,
            "completed": len(checks) - len(pending), "pending_count": len(pending),
            "pending_ids": pending[:batch_size]}
