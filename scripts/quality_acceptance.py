#!/usr/bin/env python3
"""以隔離案例的實際審查工件作為跨版本品質驗收；絕不製造 Agent 結論。"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from quality_baseline import (DEFAULT_CATALOG, PROJECT_FILE, assessment_predictions,
                              evaluate, load_catalog)
from review_queue import build_queue, load_rules

VERSION = 1
REPORT_DIR = Path("reports/security-code-review")
SOURCE_EXTS = frozenset({".cs", ".csproj", ".json", ".yaml", ".yml"})
LOWER_IS_BETTER = ("missed_fail", "false_positive_fail")
HIGHER_IS_BETTER = ("passed_count", "status_correct", "review_correct",
                    "review_gap_specific_count", "trace_complete_count",
                    "evidence_valid_count")
MAX_DIAGNOSTICS = 8


def catalog_sha256() -> str:
    """固定內建的 16 案例內容；比較結果不能混用不同題庫。"""
    return hashlib.sha256(DEFAULT_CATALOG.read_bytes()).hexdigest()


def verify_case_sources(case: dict[str, Any], directory: Path) -> list[str]:
    """核對 UTF-8 案例內容（容許跨平台 CRLF/LF），禁止其他來源變動。"""
    if not directory.is_dir():
        return ["隔離案例目錄不存在"]
    expected = {"Case.csproj": PROJECT_FILE, **case["files"]}
    problems = []
    for name, original in expected.items():
        path = directory / name
        try:
            if not path.is_file() or path.read_text(encoding="utf-8") != original:
                problems.append(f"{name}: 與固定案例原始碼不同")
        except (OSError, UnicodeError) as exc:
            problems.append(f"{name}: 無法驗證來源（{exc}）")
    for path in directory.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SOURCE_EXTS:
            continue
        relative = path.relative_to(directory)
        if relative.parts[0] in {"reports", "obj", "bin", ".git"}:
            continue
        if relative.as_posix() not in expected:
            problems.append(f"{relative.as_posix()}: 不屬於原案例的額外來源")
    return problems


def report_artifact_errors(directory: Path, data: dict) -> list[str]:
    """重新驗證正式報告 Schema、來源行號及 HTML 一致性，拒絕空白／過期報告。"""
    report = directory / REPORT_DIR / "report.json"
    date = data.get("assessment_date")
    if not isinstance(date, str) or len(date) != 10:
        return ["審查日期無效，無法驗證正式報告"]
    html = directory / REPORT_DIR / f"CodeReview_{date.replace('-', '')}.html"
    missing = [str(p.name) for p in (report, html) if not p.is_file()]
    if missing:
        return ["尚未產生正式報告：" + "、".join(missing)]
    try:
        report_data = json.loads(report.read_text(encoding="utf-8"))
        reported = report_data.get("assessment") if isinstance(report_data, dict) else None
        comparable = copy.deepcopy(data)
        # 正式產生器只允許將預設執行者名稱正規化，不可修改安全結論。
        if isinstance(reported, dict):
            report_checks = reported.get("checks")
            source_checks = comparable.get("checks")
            if (isinstance(report_checks, list) and isinstance(source_checks, list)
                    and len(report_checks) == len(source_checks)):
                for original, rendered in zip(source_checks, report_checks):
                    if (isinstance(original, dict) and isinstance(rendered, dict)
                            and original.get("reviewer") == "security-code-review-agent"
                            and isinstance(rendered.get("reviewer"), str)
                            and rendered["reviewer"].strip()):
                        original["reviewer"] = rendered["reviewer"]
        if comparable != reported:
            return ["正式 report.json 的 assessment 與目前審查資料不一致（不允許改變安全結論）"]
        command = [sys.executable, str(Path(__file__).resolve().parent / "validate_report.py"),
                   "--report", str(report), "--html", str(html),
                   "--source-root", str(directory), "--strict-sources"]
        result = subprocess.run(command, cwd=directory, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", check=False, timeout=120)
        if result.returncode:
            detail = ((result.stderr or "") + "\n" + (result.stdout or "")).strip()
            return [f"正式報告 Schema／HTML／來源驗證未通過：{detail[-800:]}"]
        return []
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired) as exc:
        return [f"無法核對正式報告：{exc}"]


def verify_review(case: dict[str, Any], directory: Path, rules: list[dict]) -> tuple[dict | None, list[str]]:
    """僅接受來源未被修改、70 條與完整性守門通過的正式 assessment 工件。"""
    problems = verify_case_sources(case, directory)
    path = directory / REPORT_DIR / "assessment.json"
    if not path.is_file():
        problems.append("尚未產生 assessment.json")
        return None, problems
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        checks = data.get("checks")
        if (not isinstance(checks, list) or len(checks) != 70
                or len({c.get("id") for c in checks if isinstance(c, dict)}) != 70
                or any((c.get("execution") or {}).get("state") != "completed"
                       for c in checks if isinstance(c, dict))):
            problems.append("70 項規則尚未全部 completed 或含重複規則")
        else:
            queue = build_queue(data, rules, 10, source_root=directory, compact=True)
            if not queue.get("ready_for_report"):
                problems.append("審查證據／完整性守門尚未全部通過")
                for key in ("review_integrity_errors", "rule_integrity_errors",
                            "safety_integrity_errors"):
                    problems.extend(str(x) for x in (queue.get(key) or [])[:MAX_DIAGNOSTICS])
                if queue.get("second_pass", {}).get("pending_count"):
                    problems.append("第二輪反向複核尚未完成")
        # 用正式驗證器檢查 report／HTML／原始碼且與目前 assessment 一致。
        problems.extend(report_artifact_errors(directory, data))
        predictions = assessment_predictions(
            directory.parent, {"cases": [case]})["cases"]
        if len(predictions) != 1:
            problems.append("指定規則無唯一 completed 結論")
            return None, problems
        return (predictions[0] if not problems else None), problems
    except (OSError, ValueError, TypeError, KeyError, AttributeError, json.JSONDecodeError) as exc:
        problems.append(f"無法驗證正式審查資料：{exc}")
        return None, problems


def compare_runs(current: dict, previous: dict) -> list[str]:
    if (not isinstance(previous, dict) or previous.get("schema_version") != VERSION
            or previous.get("measurement_source") != "review_artifacts"
            or previous.get("catalog_sha256") != current["catalog_sha256"]
            or previous.get("case_count") != current["case_count"]):
        raise ValueError("歷史品質紀錄來源、版本或固定題庫不同，不能比較")
    p_score, c_score = previous.get("score"), current.get("score")
    if not isinstance(p_score, dict) or not isinstance(c_score, dict):
        raise ValueError("歷史或目前品質紀錄缺少評分結果")
    regressions = []
    for key in LOWER_IS_BETTER:
        value, earlier = c_score.get(key), p_score.get(key)
        if type(value) is not int or type(earlier) is not int:
            raise ValueError(f"品質指標 {key} 格式不合法")
        if value > earlier:
            regressions.append(f"{key}: {earlier} → {value}（漏報或誤報增加）")
    for key in HIGHER_IS_BETTER:
        value, earlier = c_score.get(key), p_score.get(key)
        if type(value) is not int or type(earlier) is not int:
            raise ValueError(f"品質指標 {key} 格式不合法")
        if value < earlier:
            regressions.append(f"{key}: {earlier} → {value}（品質下降）")
    # 不允許曾通過的特定案例退步；平均分數不應抵銷單一已知弱點退步。
    previous_cases = previous.get("cases")
    current_cases = current.get("cases")
    if not isinstance(previous_cases, list) or not isinstance(current_cases, list):
        raise ValueError("品質案例結果格式不合法")
    old_by_id = {x["case_id"]: x for x in previous_cases}
    new_by_id = {x["case_id"]: x for x in current_cases}
    if set(old_by_id) != set(new_by_id) or len(old_by_id) != current["case_count"]:
        raise ValueError("品質案例集不一致")
    for cid, old in old_by_id.items():
        if old.get("passed") is True and new_by_id[cid].get("passed") is not True:
            regressions.append(f"{cid}: 已通過的案例出現退步")
    return regressions


def token_usage(workspace: Path, case_ids: list[str], run_id: str | None) -> dict | None:
    """不估算 Token；只統計明確指定的執行器紀錄 run_id。"""
    if run_id is None:
        return None
    count = input_total = output_total = cached_total = 0
    missing = []
    for cid in case_ids:
        path = workspace / cid / REPORT_DIR / "analysis/token-usage.jsonl"
        matched = []
        if path.is_file():
            for number, line in enumerate(path.read_text("utf-8").splitlines(), 1):
                try:
                    entry = json.loads(line)
                except (ValueError, TypeError) as exc:
                    raise ValueError(f"{cid} Token 紀錄第 {number} 行無效：{exc}") from exc
                if entry.get("run_id") == run_id:
                    inputs, outputs, cached = (entry.get("input_tokens"),
                                                entry.get("output_tokens"),
                                                entry.get("cached_input_tokens"))
                    if any(type(x) is not int or x < 0 for x in (inputs, outputs, cached)) or cached > inputs:
                        raise ValueError(f"{cid}: Token 計數不合法")
                    matched.append((inputs, outputs, cached))
        if not matched:
            missing.append(cid)
        for inputs, outputs, cached in matched:
            count += 1
            input_total += inputs
            output_total += outputs
            cached_total += cached
    return {
        "source": "executor_reported", "run_id": run_id, "records": count,
        "case_coverage": len(case_ids) - len(missing), "missing_case_ids": missing,
        "input_tokens": input_total, "output_tokens": output_total,
        "cached_input_tokens": cached_total, "total_tokens": input_total + output_total,
        "complete": not missing,
    }


def measure(workspace: Path, *, previous: dict | None = None,
            token_run_id: str | None = None) -> dict:
    workspace = workspace.resolve()
    if not workspace.is_dir():
        raise ValueError("案例工作目錄不存在；請先 materialize 並逐案例實際審查")
    catalog = load_catalog()
    _, rules = load_rules()
    accepted_predictions = []
    verification = []
    for case in catalog["cases"]:
        case_id = case["id"]
        prediction, problems = verify_review(case, workspace / case_id, rules)
        if prediction is not None:
            accepted_predictions.append(prediction)
        verification.append({
            "case_id": case_id,
            "artifacts_verified": prediction is not None,
            "diagnostics": problems[:MAX_DIAGNOSTICS],
        })
    score = evaluate(catalog, {"cases": accepted_predictions})
    case_valid = {x["case_id"]: x["artifacts_verified"] for x in verification}
    # 給每個案例加上真實工件驗收結果，而不是只相信 status 對照。
    outcomes = [{**row, "artifacts_verified": case_valid[row["case_id"]]}
                for row in score["cases"]]
    output = {
        "schema_version": VERSION,
        "measurement_source": "review_artifacts",
        "trust_limit": "來源檔與已產生審查工件可驗證；無法獨立證明代理確實閱讀或正確推理",
        "catalog_sha256": catalog_sha256(),
        "case_count": len(catalog["cases"]),
        "verified_case_count": len(accepted_predictions),
        "cases": outcomes,
        "verification": verification,
        "score": {k: v for k, v in score.items() if k != "cases"},
        "token_usage": token_usage(workspace, [c["id"] for c in catalog["cases"]], token_run_id),
    }
    regressions = compare_runs(output, previous) if previous is not None else []
    output["regressions"] = regressions
    output["quality_gate_passed"] = bool(
        score["all_passed"] and len(accepted_predictions) == len(catalog["cases"])
        and score["missed_fail"] == 0 and score["false_positive_fail"] == 0
        and not regressions
    )
    output["status"] = "accepted" if output["quality_gate_passed"] else "blocked"
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="依真實隔離審查工件驗收 16 案例、來源／證據與跨版本品質；不自行執行 AI 審查")
    parser.add_argument("--workspace", type=Path, required=True,
                        help="16 個已由 Skill 各自完成審查的隔離案例資料夾")
    parser.add_argument("--compare", type=Path, help="前次相同固定題庫的正式驗收 JSON")
    parser.add_argument("--token-run-id", help="僅統計與本次執行相關的實際 Token 紀錄")
    parser.add_argument("--output", type=Path, help="儲存機器可讀驗收 JSON")
    args = parser.parse_args(argv)
    try:
        previous = (json.loads(args.compare.read_text("utf-8")) if args.compare else None)
        result = measure(args.workspace, previous=previous, token_run_id=args.token_run_id)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", "utf-8")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["quality_gate_passed"] else 1
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"品質驗收錯誤：{exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
