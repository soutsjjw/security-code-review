#!/usr/bin/env python3
"""全 70 項品質契約盤點與真實專案報告驗收；不模擬 Agent 或製造安全判定。"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from adversarial_recheck import guidance as adversarial_guidance
from control_effectiveness import REQUIRED_SCENARIOS, guidance as control_guidance
from decision_adjudication import guidance as decision_guidance
from quality_acceptance import report_artifact_errors
from review_decision import load_decision_matrix
from review_queue import build_queue, load_rules
from review_safety import rule_scopes

VERSION = 1
REPORT_DIR = Path("reports/security-code-review")
RULE_FIELDS = ("pass_condition", "expected_evidence", "manual_boundary", "applicability")
QUALITY_VERSIONS = (
    "decision_quality_version", "cross_file_evidence_version", "control_outcome_version",
    "adversarial_quality_version", "evidence_integrity_version"
)
STATUSES = frozenset({"pass", "fail", "review", "na"})


def _read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def contract_matrix() -> dict[str, Any]:
    """覆蓋 70 項「判定邏輯／適用性／反向情境」契約，不宣稱安全測試已通過。"""
    _, rules = load_rules()
    matrix = load_decision_matrix()
    scopes = rule_scopes()
    errors: list[str] = []
    rows = []
    all_ids = {r["id"] for r in rules}
    if len(rules) != 70 or len(all_ids) != 70 or set(matrix) != all_ids or set(scopes) != all_ids:
        errors.append("70 項規則、判定矩陣或分析責任範圍不一致")
    for rule in rules:
        rid = rule["id"]
        info = matrix.get(rid, {})
        applicability = rule.get("applicability") or {}
        for field in RULE_FIELDS:
            if not isinstance(info.get(field), str) or len(info[field].strip()) < 5:
                errors.append(f"{rid}: 判定矩陣缺少具體 {field}")
        for field in ("must_assess_when", "may_be_not_applicable_when"):
            if not isinstance(applicability.get(field), str) or len(applicability[field].strip()) < 5:
                errors.append(f"{rid}: 缺少 {field}，不能完成適用性判定")
        if applicability.get("no_evidence") != "review":
            errors.append(f"{rid}: 無證據時不可自動 pass/na/fail")
        scenarios = REQUIRED_SCENARIOS.get(rid)
        if not isinstance(scenarios, tuple) or len(scenarios) < 2 or len(set(scenarios)) != len(scenarios):
            errors.append(f"{rid}: 缺少獨立且具體的兩類反向攻擊／失效情境")
            scenarios = ()
        if any(s in {"alternate_or_bypass_path", "generic_bypass"} for s in scenarios):
            errors.append(f"{rid}: 繞過情境不可沿用泛用預設值")
        guidance = control_guidance(rid)
        if list(scenarios) != guidance["required_scenarios"]:
            errors.append(f"{rid}: 安全控制提示與品質契約不一致")
        if not guidance.get("required_for_fail") or not guidance.get("required_for_review"):
            errors.append(f"{rid}: 缺少 Fail／Review 控制證據契約")
        reverse = adversarial_guidance(rid)
        if reverse.get("required_hypotheses") not in {1, 2}:
            errors.append(f"{rid}: 缺少第二輪最低反例數量")
        adjudication = decision_guidance(rid)
        if not adjudication:
            errors.append(f"{rid}: 缺少外部缺口／判定裁決指引")
        rows.append({
            "rule_id": rid, "mode": info.get("mode"),
            "scope": scopes.get(rid),
            "applicability_cases": ["applicable", "not_applicable", "insufficient_evidence"],
            "decision_paths": ["pass", "fail", "review", "na"],
            "scenario_types": list(scenarios),
            "second_pass_hypotheses": reverse.get("required_hypotheses"),
            "contract_valid": not any(e.startswith(f"{rid}:") for e in errors),
        })
    return {
        "schema_version": VERSION,
        "measurement_source": "static_quality_contracts",
        "meaning": "僅驗證 70 項判定／適用性／反例證據契約，不代表 Agent 已審查真實專案",
        "rule_count": len(rows),
        "valid_count": sum(x["contract_valid"] for x in rows),
        "errors": errors,
        "rows": rows,
        "passed": not errors and len(rows) == 70 and set(x["rule_id"] for x in rows) == all_ids,
    }


def source_fingerprint(snapshot: dict) -> str:
    source = snapshot.get("source_hashes")
    if not isinstance(source, dict) or not source:
        raise ValueError("來源快照缺少 source_hashes")
    payload = {"git_revision": snapshot.get("git_revision"), "source_hashes": source}
    return hashlib.sha256(json.dumps(
        payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")).hexdigest()


def compare_project(current: dict, earlier: dict) -> list[str]:
    """只比較相同來源版本。安全判定變動不以 Review 數量多寡論斷。"""
    if (not isinstance(earlier, dict) or earlier.get("schema_version") != VERSION
            or earlier.get("measurement_source") != "real_project_artifacts"
            or earlier.get("project_id") != current["project_id"]
            or earlier.get("source_fingerprint") != current["source_fingerprint"]
            or earlier.get("rule_ids") != current["rule_ids"]):
        raise ValueError("舊結果來源版本／規則／專案不同，不得比較安全結論")
    if earlier.get("status") != "accepted":
        raise ValueError("只能與已通過真實工件驗收的前一版結果比較")
    previous = earlier.get("per_rule")
    actual = current.get("per_rule")
    if not isinstance(previous, dict) or not isinstance(actual, dict):
        raise ValueError("缺少真實逐規則判定紀錄")
    errors: list[str] = []
    for rid in current["rule_ids"]:
        if rid not in actual or rid not in previous:
            errors.append(f"{rid}: 前後版本缺少判定")
            continue
        past, now = previous[rid], actual[rid]
        if not isinstance(past, dict) or not isinstance(now, dict):
            errors.append(f"{rid}: 判定結構無效")
            continue
        if past.get("status") == "fail" and now.get("status") != "fail":
            errors.append(f"{rid}: 既有 Fail 變成 {now.get('status')}，須額外人工裁決")
        past_finding_ids = past.get("finding_ids")
        now_finding_ids = now.get("finding_ids")
        if not isinstance(past_finding_ids, list) or not isinstance(now_finding_ids, list):
            errors.append(f"{rid}: Finding 參照資料無效")
            continue
        if not set(past_finding_ids) <= set(now_finding_ids):
            errors.append(f"{rid}: 原有 Finding 參照減少，須確認並保留證據")
        if past.get("status") == "fail" and now.get("source_evidence_count", 0) == 0:
            errors.append(f"{rid}: 原有 Fail 失去正式來源證據")
    previous_coverage = earlier.get("coverage", {})
    now_coverage = current.get("coverage", {})
    if (isinstance(previous_coverage, dict) and isinstance(now_coverage, dict)
            and type(previous_coverage.get("reviewed_source_file_count")) is int
            and type(now_coverage.get("reviewed_source_file_count")) is int
            and now_coverage["reviewed_source_file_count"] <
            previous_coverage["reviewed_source_file_count"]):
        errors.append("已核對來源檔數量退步")
    return errors


def measure(target: Path, *, previous: dict | None = None,
            skip_contracts: bool = False) -> dict[str, Any]:
    target = target.resolve()
    if not target.is_dir():
        raise ValueError("受測專案目錄不存在")
    contract = contract_matrix()
    if not skip_contracts and not contract["passed"]:
        raise ValueError("70 項共用品質契約驗證失敗：" + "；".join(contract["errors"][:5]))
    base = target / REPORT_DIR
    assessment_path = base / "assessment.json"
    index_path = base / "analysis/structure-index.json"
    snapshot_path = base / "analysis/review-snapshot.json"
    if any(not x.is_file() for x in (assessment_path, index_path, snapshot_path)):
        raise ValueError("缺少正式 assessment、結構索引或來源快照，不能宣稱真實驗收")
    assessment = _read(assessment_path)
    index = _read(index_path)
    snapshot = _read(snapshot_path)
    if not all(isinstance(x, dict) for x in (assessment, index, snapshot)):
        raise ValueError("審查工件格式錯誤")
    _, rules = load_rules()
    rule_ids = sorted(r["id"] for r in rules)
    checks = assessment.get("checks")
    if (not isinstance(checks, list) or len(checks) != 70 or
            len({c.get("id") for c in checks if isinstance(c, dict)}) != 70 or
            {c.get("id") for c in checks if isinstance(c, dict)} != set(rule_ids)):
        raise ValueError("正式 assessment 必須有完整且唯一的 70 項規則")
    problems = [
        f"{field} 未啟用；須用新版分析索引完整重審"
        for field in QUALITY_VERSIONS if index.get(field) != 1
    ]
    try:
        queue = build_queue(assessment, rules, 10, source_root=target, compact=True)
    except (ValueError, TypeError, KeyError, OSError) as exc:
        raise ValueError(f"真實來源與審查守門無法驗證：{exc}") from exc
    for key in ("review_integrity_errors", "rule_integrity_errors", "safety_integrity_errors"):
        problems.extend(str(x) for x in queue.get(key, []))
    if queue.get("completed") != 70 or not queue.get("ready_for_report"):
        problems.append("70/70 completed、來源覆蓋或證據完整性尚未全部通過")
    second = queue.get("second_pass") or {}
    if not second.get("enabled") or not second.get("baseline_ready") or second.get("pending_count") != 0:
        problems.append("第二輪反向複核未完成或證據不合格")
    problems.extend(report_artifact_errors(target, assessment))
    coverage = queue.get("source_coverage") or {}
    if coverage.get("missing_source_file_count") != 0 or (
            coverage.get("source_file_count", 0) != coverage.get("reviewed_source_file_count", -1)):
        problems.append("來源覆蓋率未達 100%")
    statuses = Counter(c.get("status", "invalid") for c in checks)
    findings = {f.get("id"): f for f in assessment.get("findings", [])
                if isinstance(f, dict) and isinstance(f.get("id"), str)}
    per_rule = {}
    for check in checks:
        rid = check["id"]
        evidences = check.get("evidence") or []
        references = check.get("finding_ids") or []
        if not isinstance(evidences, list) or not isinstance(references, list):
            problems.append(f"{rid}: 正式 evidence 或 finding_ids 格式無效")
            evidences, references = [], []
        if check.get("status") == "fail" and (
                not references or any(fid not in findings for fid in references)):
            problems.append(f"{rid}: Fail 缺少可核對的 Finding")
        per_rule[rid] = {
            "status": check.get("status"),
            "execution_state": (check.get("execution") or {}).get("state"),
            "finding_ids": sorted(x for x in references if isinstance(x, str)),
            "source_evidence_count": sum(
                isinstance(e, dict) and e.get("kind") in {"source", "configuration"}
                for e in evidences
            ),
            "external_evidence_count": sum(
                isinstance(e, dict) and e.get("kind") not in {"source", "configuration"}
                for e in evidences
            ),
        }
    if set(statuses) - STATUSES:
        problems.append("審查狀態包含不合法值")
    result = {
        "schema_version": VERSION,
        "measurement_source": "real_project_artifacts",
        "trust_limit": "工件、來源與結果完整性可核對；不能單獨證明代理分析正確或有實際攻擊重現",
        "project_id": assessment.get("project_id") or target.name,
        "git_revision": snapshot.get("git_revision"),
        "source_fingerprint": source_fingerprint(snapshot),
        "rule_ids": rule_ids,
        "contracts": {"count": contract["rule_count"], "valid_count": contract["valid_count"]},
        "coverage": coverage,
        "status_counts": dict(sorted(statuses.items())),
        "finding_count": len(findings),
        "verified_second_pass_count": second.get("completed") if second.get("pending_count") == 0 else 0,
        "per_rule": per_rule,
        "diagnostics": problems[:100],
    }
    regressions = compare_project(result, previous) if previous is not None else []
    result["regressions"] = regressions
    result["quality_gate_passed"] = not problems and not regressions
    result["status"] = "accepted" if result["quality_gate_passed"] else "blocked"
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="檢核全 70 項規則契約，或驗收已由 Agent 完成的真實專案與報告")
    parser.add_argument("--matrix-only", action="store_true", help="僅驗證 70 條規則品質契約")
    parser.add_argument("--target", type=Path, help="已完成完整審查的真實專案根目錄")
    parser.add_argument("--compare", type=Path, help="相同 Git 來源版本的前次真實驗收 JSON")
    parser.add_argument("--output", type=Path, help="將驗收結果存為 JSON")
    args = parser.parse_args(argv)
    if args.matrix_only == bool(args.target) or (args.matrix_only and args.compare):
        parser.error("須擇一指定 --matrix-only 或 --target；比較僅供真實專案驗收")
    try:
        previous = _read(args.compare) if args.compare else None
        result = contract_matrix() if args.matrix_only else measure(args.target, previous=previous)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", "utf-8")
        visible = result
        if args.matrix_only and args.output:
            visible = {
                "measurement_source": result["measurement_source"],
                "rule_count": result["rule_count"],
                "valid_count": result["valid_count"],
                "passed": result["passed"],
                "errors": result["errors"],
                "full_matrix": str(args.output),
            }
        print(json.dumps(visible, ensure_ascii=False, indent=2))
        return 0 if (result["passed"] if args.matrix_only else result["quality_gate_passed"]) else 1
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        print("品質驗收錯誤：" + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
