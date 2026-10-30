#!/usr/bin/env python3
"""G1 / E2E evidence-based acceptance. No synthetic pass or automatic source edits.

G1 verifies real first-pass gate, second-pass baseline, Findings preservation,
legacy integrity and shadow differences. E2E delegates to existing strict
quality_gate.measure (70 rules, second pass, report and coverage).
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

from adversarial_recheck import first_pass_issues
from evidence_integrity import errors as integrity_errors
from review_safety import snapshot_errors
from quality_gate import measure as quality_measure
from execution_boundary_events import verify_run
from review_core import snapshot_fingerprint

REPORT = Path("reports/security-code-review")
KEYS = ("ready_for_second_pass", "pending_rule_ids", "missing_source_file_count",
        "recheck_rule_ids")

def read(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("必要測試工件缺失或為 symlink：" + str(path))
    return json.loads(path.read_text(encoding="utf-8"))

def finding_hash(finding):
    return hashlib.sha256(json.dumps(finding, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":")).encode("utf-8")).hexdigest()

def preservation(before, after):
    original = {x["id"]: finding_hash(x) for x in before.get("findings", [])}
    current = {x["id"]: finding_hash(x) for x in after.get("findings", [])}
    # Validate the authorized amendment hash chain, not just a reviewer label.
    entries = [a for a in after.get("finding_amendments", []) if isinstance(a, dict)]
    def valid_revision(fid):
        known = original[fid]
        seen = set()
        while known != current[fid]:
            matches = [a for a in entries if a.get("finding_id") == fid
                       and a.get("previous_sha256") == known
                       and a.get("updated_sha256") not in seen
                       and isinstance(a.get("reason"), str) and len(a["reason"].strip()) >= 40
                       and isinstance(a.get("reviewer"), str) and len(a["reviewer"].strip()) >= 4
                       and isinstance(a.get("previous_finding"), dict)
                       and finding_hash(a["previous_finding"]) == known]
            if len(matches) != 1:
                return False
            known = matches[0]["updated_sha256"]
            seen.add(known)
        return True
    missing = sorted(set(original) - set(current))
    modified = sorted(fid for fid in original.keys() & current.keys()
                      if original[fid] != current[fid] and not valid_revision(fid))
    return missing, modified

def compare_shadow(legacy, optimized):
    """Fail closed on unadjudicated safety-diagnostic differences."""
    errors = []
    for key in KEYS:
        if legacy.get(key) != optimized.get(key):
            errors.append("shadow 欄位差異：" + key)
    if (legacy.get("blocker_signature") and optimized.get("blocker_signature")
            and legacy["blocker_signature"] != optimized["blocker_signature"]):
        errors.append("shadow 正式 Blocker 指紋差異")
    for key in ("blockers",):
        def shape(obj):
            return sorted((x.get("category"), tuple(sorted(x.get("rule_ids") or [])))
                          for x in obj.get(key, []) if isinstance(x, dict))
        if shape(legacy) != shape(optimized):
            errors.append("shadow Blocker 類型／責任差異")
    return errors

def g1(target, *, before_path, shadow_legacy, shadow_optimized, legacy_target,
       require_second_pass=True):
    target = Path(target).resolve()
    assessment = read(target / REPORT / "assessment.json")
    before = read(before_path)
    checks = []
    def check(name, ok, error=None):
        checks.append({"id": name, "passed": bool(ok), "reason": None if ok else str(error or name)})
    missing, modified = preservation(before, assessment)
    check("findings_preserved", not missing and not modified,
          f"遺失 {missing}／未授權修改 {modified}")
    try:
        from evidence_integrity import enabled as integrity_enabled
        problems = integrity_errors(target) + snapshot_errors(target)
        if not integrity_enabled(target):
            problems.append("未啟用正式 Manifest／Journal 完整性")
        check("integrity_verified", not problems, problems[:5])
    except (OSError, ValueError, TypeError, KeyError) as exc:
        check("integrity_verified", False, type(exc).__name__)
    try:
        errors = first_pass_issues(target, assessment, allow_partial=False)
        check("full_gate_passed", not errors, errors[:5])
    except (OSError, ValueError, TypeError, KeyError) as exc:
        check("full_gate_passed", False, str(exc)[:250])
    # Must match the formal checkpoint contract, not merely an arbitrary JSON file.
    try:
        checkpoint = read(target / REPORT / "analysis/first-pass-baseline.json")
        snapshot = read(target / REPORT / "analysis/review-snapshot.json")
        from review_queue import load_rules
        _, rules = load_rules()
        expected_ids = {r["id"] for r in rules}
        expected = (checkpoint.get("snapshot_fingerprint") == snapshot_fingerprint(snapshot)
                    and isinstance(checkpoint.get("checks"), dict)
                    and set(checkpoint["checks"]) == expected_ids
                    and isinstance(assessment.get("checks"), list)
                    and {c.get("id") for c in assessment["checks"] if isinstance(c, dict)} == expected_ids)
        check("second_pass_started", expected,
              "第二輪 baseline 的快照／70 項規則錨點不一致")
    except (OSError, ValueError, TypeError, KeyError) as exc:
        check("second_pass_started", False, type(exc).__name__)
    try:
        old, new = read(shadow_legacy), read(shadow_optimized)
        differences = compare_shadow(old, new)
        check("shadow_equivalent", not differences, differences)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        check("shadow_equivalent", False, type(exc).__name__)
    try:
        legacy = Path(legacy_target).resolve()
        if legacy == target:
            raise ValueError("必須使用獨立舊格式中途狀態")
        legacy_state = read(legacy / REPORT / "assessment.json")
        from evidence_integrity import enabled as integrity_enabled
        issues = integrity_errors(legacy)
        old_ids = {f["id"] for f in legacy_state.get("findings", [])}
        check("legacy_state_resumable", integrity_enabled(legacy) and not issues and
              all(f["id"] in old_ids for f in before.get("findings", [])),
              "舊格式狀態未核對／Findings 不完整")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        check("legacy_state_resumable", False, type(exc).__name__)
    pending_boundary_batches = []
    try:
        latest = read(target / REPORT / "logs/latest.json")
        result = verify_run(target, latest["run_id"])
        pending_boundary_batches = list(result["blocked_batches"])
        check("boundary_blocks_resolved", not result["blocked_batches"],
              result["blocked_batches"])
        from execution_boundary import scripts as current_executables
        baseline = read(target / REPORT / "logs/boundary-baselines" /
                        (latest["run_id"] + ".json"))
        boundary_level = baseline["inventory"]["boundary_level"]
        if not isinstance(baseline.get("scripts"), dict):
            raise ValueError("缺少可信的原始腳本清單")
        no_script_changes = current_executables(target) == baseline["scripts"]
        check("no_unreviewed_executable_changes", no_script_changes,
              "analysis 執行檔新增／移除／SHA256 異動")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        boundary_level = "unverified"
        check("boundary_blocks_resolved", False, type(exc).__name__)
    checks.append({"id": "boundary_assurance", "passed": boundary_level in ("L1", "L2", "L3"),
                   "reason": "L3 僅表示未偵測到違規，非強制隔離"
                   if boundary_level == "L3" else None})
    passed = all(x["passed"] for x in checks)
    gate_status = ("accepted" if passed else
                   "blocked_pending_review" if pending_boundary_batches else "blocked")
    results = {item["id"]: item["passed"] for item in checks}
    full_gate_passed = results.get("full_gate_passed", False) and results.get("integrity_verified", False)
    ready_for_second_pass = full_gate_passed and results.get("second_pass_started", False)
    return {"schema_version": 1, "kind": "g1", "status": gate_status,
            "accepted": passed, "incremental_clean": False,
            "full_gate_passed": bool(full_gate_passed),
            "ready_for_second_pass": bool(ready_for_second_pass),
            "checks": checks, "boundary_level": boundary_level,
            "assurance": "conditional-audit-only" if boundary_level == "L3" else
                         "verified" if boundary_level in ("L1", "L2") else "unverified",
            "note": "G1 只證明交付的真實工件符合流程守門；不聲稱模型安全判定正確"}

def e2e(target, *, previous_quality=None):
    """Authoritative end-to-end quality gate, never substitute a unit-test fixture."""
    result = quality_measure(Path(target), previous=previous_quality)
    return {"schema_version": 1, "kind": "e2e", "accepted": result["quality_gate_passed"],
            "status": "accepted" if result["quality_gate_passed"] else "blocked",
            "measurement_source": result["measurement_source"],
            "source_fingerprint": result["source_fingerprint"],
            "coverage": result["coverage"],
            "verified_second_pass_count": result["verified_second_pass_count"],
            "finding_count": result["finding_count"],
            "diagnostics": result["diagnostics"],
            "regressions": result["regressions"]}

def main():
    p = argparse.ArgumentParser(description="G1 灰度與 E2E 真實工件驗收")
    p.add_argument("--target", required=True, type=Path)
    p.add_argument("--mode", choices=("g1", "e2e"), required=True)
    p.add_argument("--before-assessment", type=Path)
    p.add_argument("--shadow-legacy", type=Path)
    p.add_argument("--shadow-optimized", type=Path)
    p.add_argument("--legacy-target", type=Path)
    p.add_argument("--previous-quality", type=Path)
    p.add_argument("--output", type=Path)
    a = p.parse_args()
    try:
        if a.mode == "g1":
            if any(x is None for x in (a.before_assessment, a.shadow_legacy,
                                        a.shadow_optimized, a.legacy_target)):
                p.error("G1 需提供 --before-assessment、--shadow-legacy、--shadow-optimized 與 --legacy-target")
            report = g1(a.target, before_path=a.before_assessment,
                        shadow_legacy=a.shadow_legacy, shadow_optimized=a.shadow_optimized,
                        legacy_target=a.legacy_target)
        else:
            report = e2e(a.target, previous_quality=read(a.previous_quality)
                         if a.previous_quality else None)
        if a.output:
            a.output.parent.mkdir(parents=True, exist_ok=True)
            a.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", "utf-8")
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if report["accepted"] else 1
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        p.exit(2, "正式驗收無法完成：" + str(exc) + "\n")

if __name__ == "__main__":
    raise SystemExit(main())
