#!/usr/bin/env python3
"""P0 已知答案基準：隔離案例、比對實際審查結果，不替 Agent 判定安全性。"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATALOG = ROOT / "tests/fixtures/p0-quality-baseline/cases.json"
PROJECT_FILE = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
  </PropertyGroup>
  <ItemGroup>
    <FrameworkReference Include="Microsoft.AspNetCore.App" />
  </ItemGroup>
</Project>
"""
STATUSES = {"pass", "fail", "review", "na"}
_RULE_ID = re.compile(r"^(?:AC|AU|IN|CR|EH|LG|DP|PD|BC|SI)-\\d{2}$")


def _relative_path(value: Any) -> str:
    if not isinstance(value, str) or not value or "\\\\" in value or "\\x00" in value:
        raise ValueError("檔案路徑無效")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {".", ".."} for part in value.split("/")):
        raise ValueError(f"禁止不安全路徑：{value}")
    if ":" in value or value.startswith("~"):
        raise ValueError(f"禁止不安全路徑：{value}")
    return value


def load_catalog(path: Path = DEFAULT_CATALOG) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("P0 案例集版本錯誤")
    rows = data.get("cases")
    if not isinstance(rows, list) or not rows:
        raise ValueError("P0 案例集不可為空")
    rule_ids = {r["id"] for r in json.loads((ROOT / "rules.json").read_text(encoding="utf-8"))["rules"]}
    ids: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("案例必須是物件")
        case_id = row.get("id")
        if (not isinstance(case_id, str) or not re.fullmatch(r"[a-z][a-z0-9-]+", case_id)
                or case_id in ids):
            raise ValueError(f"案例 ID 重複或不合法：{case_id}")
        ids.add(case_id)
        rule_id = row.get("rule_id")
        if not isinstance(rule_id, str) or not _RULE_ID.fullmatch(rule_id) or rule_id not in rule_ids:
            raise ValueError(f"{case_id}: 未知規則 {rule_id}")
        status = row.get("expected_status")
        if status not in {"pass", "fail", "review"} or row.get("expected_finding") is not (status == "fail"):
            raise ValueError(f"{case_id}: 狀態與 Finding 期望不一致")
        files = row.get("files")
        required = row.get("required_paths")
        anchor = row.get("anchor")
        if not isinstance(files, dict) or not files or not isinstance(required, list) or not required:
            raise ValueError(f"{case_id}: 缺少來源檔或控制鏈")
        for filename, body in files.items():
            _relative_path(filename)
            if filename == "Case.csproj" or not filename.endswith((".cs", ".json", ".yaml", ".yml")):
                raise ValueError(f"{case_id}: 不支援的來源檔：{filename}")
            if not isinstance(body, str) or not body.strip():
                raise ValueError(f"{case_id}: 來源內容為空：{filename}")
        if len(set(required)) != len(required) or any(p not in files for p in required):
            raise ValueError(f"{case_id}: 必查路徑未包含在案例來源")
        if (not isinstance(anchor, dict) or anchor.get("path") not in required
                or not isinstance(anchor.get("text"), str) or not anchor["text"].strip()):
            raise ValueError(f"{case_id}: 缺少可定位的人工核定錨點")
        if files[anchor["path"]].count(anchor["text"]) != 1:
            raise ValueError(f"{case_id}: 錨點不存在或不唯一")
        if not isinstance(row.get("rationale"), str) or len(row["rationale"]) < 15:
            raise ValueError(f"{case_id}: 缺少人工預期判定理由")
        if status == "review" and not row.get("external_artifact"):
            raise ValueError(f"{case_id}: review 必須指名儲存庫外工件")
    return data


def materialize(target: Path, catalog: dict[str, Any]) -> dict[str, Any]:
    target = target.resolve()
    if target.exists() and any(target.iterdir()):
        raise ValueError("輸出目錄不是空的；避免覆寫既有受測專案或審查結果")
    target.mkdir(parents=True, exist_ok=True)
    for case in catalog["cases"]:
        directory = target / case["id"]
        directory.mkdir()
        (directory / "Case.csproj").write_text(PROJECT_FILE, encoding="utf-8")
        for name, body in case["files"].items():
            dest = directory / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(body, encoding="utf-8")
    return {"case_count": len(catalog["cases"]), "materialized_root": str(target)}


def assessment_predictions(target: Path, catalog: dict[str, Any]) -> dict[str, Any]:
    """讀取每個隔離專案真實產出的 assessment.json；缺少的結果保持 missing。"""
    predictions = []
    for case in catalog["cases"]:
        path = target / case["id"] / "reports/security-code-review/assessment.json"
        if not path.is_file():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        matches = [check for check in data.get("checks", []) if check.get("id") == case["rule_id"]]
        if len(matches) != 1:
            raise ValueError(f"{case['id']}: 找不到唯一的 {case['rule_id']} 規則結論")
        check = matches[0]
        finding_ids = set(check.get("finding_ids") or [])
        has_finding = bool(finding_ids) or any(
            case["rule_id"] in (finding.get("check_ids") or [])
            for finding in data.get("findings", []) if isinstance(finding, dict)
        )
        predictions.append({
            "case_id": case["id"], "status": check.get("status"),
            "finding": has_finding,
            "inspected_paths": (check.get("execution") or {}).get("inspected_paths", []),
            "evidence": [
                {"path": e.get("path"), "line_start": e.get("line_start"),
                 "line_end": e.get("line_end")}
                for e in check.get("evidence", []) if isinstance(e, dict)
                and e.get("kind") in {"source", "configuration"}
            ],
        })
    return {"cases": predictions}


def _valid_evidence(case: dict[str, Any], evidence: Any) -> bool:
    if not isinstance(evidence, list):
        return False
    for item in evidence:
        if not isinstance(item, dict) or item.get("path") not in case["files"]:
            continue
        start, end = item.get("line_start"), item.get("line_end")
        count = len(case["files"][item["path"]].splitlines())
        if type(start) is int and type(end) is int and 1 <= start <= end <= count:
            return True
    return False


def evaluate(catalog: dict[str, Any], predictions: dict[str, Any]) -> dict[str, Any]:
    """量測規則結論／Finding／控制鏈；不假裝自動證明語意安全。"""
    if not isinstance(predictions, dict) or not isinstance(predictions.get("cases"), list):
        raise ValueError("預測資料需要 cases 陣列")
    expected = {item["id"]: item for item in catalog["cases"]}
    observed: dict[str, dict[str, Any]] = {}
    for row in predictions["cases"]:
        if not isinstance(row, dict) or row.get("case_id") not in expected:
            raise ValueError("包含未知或無效的案例 ID")
        case_id = row["case_id"]
        if case_id in observed:
            raise ValueError(f"案例重複提交：{case_id}")
        if row.get("status") not in STATUSES:
            raise ValueError(f"{case_id}: 不合法的規則狀態")
        if type(row.get("finding")) is not bool:
            raise ValueError(f"{case_id}: Finding 必須為布林值")
        if not isinstance(row.get("inspected_paths"), list):
            raise ValueError(f"{case_id}: inspected_paths 必須是陣列")
        observed[case_id] = row

    outcomes = []
    misses = false_positives = 0
    predicted_fail = correct_fail = 0
    for case_id, case in expected.items():
        row = observed.get(case_id)
        status = row["status"] if row else None
        status_match = status == case["expected_status"]
        finding_match = bool(row is not None and row["finding"] == case["expected_finding"])
        required_paths = set(case["required_paths"])
        inspected = set(row.get("inspected_paths", [])) if row else set()
        trace_complete = bool(row is not None and required_paths.issubset(inspected))
        evidence_valid = bool(row is not None and _valid_evidence(case, row.get("evidence")))
        # 錨點只做參考，不要求所有正確審查一定引用同一行。
        anchor = case["anchor"]
        anchor_line = next(
            n for n, line in enumerate(case["files"][anchor["path"]].splitlines(), 1)
            if anchor["text"] in line
        )
        anchor_cited = bool(row and any(
            e.get("path") == anchor["path"]
            and type(e.get("line_start")) is int and type(e.get("line_end")) is int
            and e["line_start"] <= anchor_line <= e["line_end"]
            for e in row.get("evidence", []) if isinstance(e, dict)
        ))
        if case["expected_status"] == "fail" and status != "fail":
            misses += 1
        if status == "fail":
            predicted_fail += 1
            if case["expected_status"] == "fail":
                correct_fail += 1
            else:
                false_positives += 1
        outcomes.append({
            "case_id": case_id, "rule_id": case["rule_id"], "expected": case["expected_status"],
            "actual": status, "status_match": status_match, "finding_match": finding_match,
            "trace_complete": trace_complete, "evidence_valid": evidence_valid,
            "anchor_cited": anchor_cited,
            "passed": all((status_match, finding_match, trace_complete, evidence_valid)),
        })
    total = len(outcomes)
    known_fail = sum(case["expected_status"] == "fail" for case in expected.values())
    true_status = sum(x["status_match"] for x in outcomes)
    return {
        "schema_version": 1,
        "case_count": total, "received": len(observed),
        "status_correct": true_status, "status_accuracy": round(true_status / total, 4),
        "known_fail_count": known_fail, "missed_fail": misses,
        "fail_recall": round(correct_fail / known_fail, 4) if known_fail else None,
        "predicted_fail_count": predicted_fail, "false_positive_fail": false_positives,
        "fail_precision": round(correct_fail / predicted_fail, 4) if predicted_fail else None,
        "review_correct": sum(x["status_match"] and x["expected"] == "review" for x in outcomes),
        "review_count": sum(x["expected"] == "review" for x in outcomes),
        "trace_complete_count": sum(x["trace_complete"] for x in outcomes),
        "evidence_valid_count": sum(x["evidence_valid"] for x in outcomes),
        "passed_count": sum(x["passed"] for x in outcomes),
        "all_passed": all(x["passed"] for x in outcomes),
        "cases": outcomes,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="P0 正確性基準，不改動受測專案原始碼")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--materialize", type=Path, metavar="EMPTY_DIR")
    group.add_argument("--evaluate", type=Path, metavar="PREDICTIONS_JSON")
    group.add_argument("--assessments", type=Path, metavar="CASE_WORKSPACE_ROOT")
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--output", type=Path, help="額外寫出 JSON 比對結果")
    args = parser.parse_args(argv)
    try:
        catalog = load_catalog(args.catalog)
        if args.materialize:
            result = materialize(args.materialize, catalog)
            code = 0
        else:
            predictions = (json.loads(args.evaluate.read_text(encoding="utf-8"))
                           if args.evaluate else assessment_predictions(args.assessments, catalog))
            result = evaluate(catalog, predictions)
            code = 0 if result["all_passed"] else 1
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return code
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        print(f"P0 quality baseline error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
