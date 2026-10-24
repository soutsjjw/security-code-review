#!/usr/bin/env python3
"""只產生單一分類的經驗證 HTML/JSON 部分審查報告；絕不產生 70 項正式報告。

P4 將 P3 的跨檔／控制／外部裁決／第二輪守門視為先決條件，
不以 Schema 或 HTML 渲染成功取代真實程式碼審查。
"""
from __future__ import annotations

import argparse
from collections import Counter
from html import escape
import json
from pathlib import Path
import sys
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from partial_review import (_artifact, _atomic, _snapshot, read_category, STAGED_FILE)
from partial_review_safety import validate as validate_safety
from report_common import ROOT, extract_html_report, render_html
from review_scope import (CATEGORIES, ScopeError, load_catalog, parse_categories,
                          build_scope_plan, validate_catalog)
from source_coverage import build_source_coverage
from source_reader import read_source_text

SCHEMA_DIR = ROOT / "schemas"
TEMPLATE_PATH = ROOT / "templates/partial-security-report.html"
REPORT_FILE = Path("report.json")
LIMITATIONS = [
    "僅審查指定分類，其他 AC～SI 分類未在本報告進行安全判定。",
    "程式碼靜態審查不能直接證明部署、運作政策或外部服務符合性。",
    "本報告不代表完整 70 項審查，也不代表附件或外部防護基準已通過。",
]
STATUSES = {"pass": "通過", "fail": "不符合", "review": "待確認", "na": "不適用"}
SEVERITIES = {"critical": "重大", "high": "高", "medium": "中", "low": "低", "info": "資訊"}


def _schema_validator() -> Draft202012Validator:
    formal = json.loads((SCHEMA_DIR / "assessment.schema.json").read_text("utf-8"))
    assessment = json.loads((SCHEMA_DIR / "partial-assessment.schema.json").read_text("utf-8"))
    report = json.loads((SCHEMA_DIR / "partial-report.schema.json").read_text("utf-8"))
    for item in (formal, assessment, report):
        Draft202012Validator.check_schema(item)
    registry = Registry().with_resources([
        ("assessment.schema.json", Resource.from_contents(formal)),
        ("partial-assessment.schema.json", Resource.from_contents(assessment)),
    ])
    return Draft202012Validator(report, registry=registry, format_checker=FormatChecker())


def _expected(category: str, catalog: dict[str, Any]) -> list[dict[str, Any]]:
    validate_catalog(catalog)
    if category not in CATEGORIES:
        raise ScopeError(f"未知分類：{category}")
    return [r for r in catalog["rules"] if r["category"] == category]


def _check_source_evidence(root: Path, report: dict[str, Any], snapshot: dict[str, Any]) -> list[str]:
    """檢查可定位來源證據的快照歸屬、路徑及行號，不能只檢查 JSON 字串。"""
    known = snapshot["source_hashes"]
    errors: list[str] = []
    reviewed = report["assessment"]["file_reviews"]
    verified_paths = {r["path"] for r in reviewed}
    checks = report["assessment"]["checks"]
    for rule in [*checks, *report["assessment"]["findings"]]:
        label = rule["id"]
        for number, proof in enumerate(rule.get("evidence", [])):
            if not isinstance(proof, dict) or proof.get("kind") not in ("source", "configuration"):
                continue
            path = proof.get("path")
            start, end = proof.get("line_start"), proof.get("line_end")
            if (not isinstance(path, str) or path not in known or path not in verified_paths
                    or type(start) is not int or type(end) is not int or start < 1 or end < start):
                errors.append(f"{label}: 來源證據[{number}] 路徑或行號無效／未列入逐檔查證")
                continue
            resolved = (root / path).resolve()
            if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
                errors.append(f"{label}: 來源證據[{number}] 指向不安全的檔案")
                continue
            try:
                lines = read_source_text(resolved)[0].splitlines()
            except (OSError, UnicodeError, ValueError) as exc:
                errors.append(f"{label}: 無法核對來源證據[{number}]：{exc}")
                continue
            if end > len(lines):
                errors.append(f"{label}: 來源證據[{number}] 行號超出實際來源")
    return errors


def build_report(root: Path, category: str, catalog: dict[str, Any]) -> dict[str, Any]:
    """生成內存物件之前先核對 P3 安全品質；不觸碰任何現有報告。"""
    rules = _expected(category, catalog)
    assessment = read_category(root, category, catalog)
    if _artifact(root, category, STAGED_FILE).exists():
        raise ScopeError(f"{category}: 尚有 staged 交易未整合，不能產生部分報告")
    safety = validate_safety(root, category, catalog)
    if (not safety["safety_valid"] or not safety["first_pass_complete"]
            or safety["remaining_ids"] or not safety["second_pass"]["baseline_ready"]
            or safety["second_pass"]["pending_count"] or safety["safety_integrity_errors"]):
        issues = safety["safety_integrity_errors"][:8]
        raise ScopeError(f"{category}: P3 第一輪或第二輪安全守門未通過：{issues} "
                         f"remaining={safety['remaining_ids']} second={safety['second_pass']['pending_ids']}")
    coverage = build_source_coverage(assessment, root, selected_categories=(category,))
    if coverage["missing_source_file_count"] or coverage["review_integrity_errors"]:
        raise ScopeError(f"{category}: 逐檔來源覆蓋不完整："
                         + "；".join(coverage["review_integrity_errors"][:6]))
    checks = assessment["checks"]
    counters = Counter(c["status"] for c in checks)
    report = {
        "report_schema_version": "partial-1.0",
        "review_mode": "partial",
        "category": category,
        "ruleset_version": catalog["ruleset_version"],
        "project": {
            "project_id": assessment["project_id"],
            "git_revision": assessment["git_revision"],
            "assessment_date": assessment["assessment_date"],
        },
        "source_snapshot_sha256": assessment["source_snapshot_sha256"],
        "rules": [{"id": r["id"], "title": r["title"], "category": r["category"]} for r in rules],
        "summary": {
            "total": len(checks), "completed": sum(c["execution"]["state"] == "completed" for c in checks),
            **{state: counters.get(state, 0) for state in STATUSES},
            "findings": len(assessment["findings"]),
        },
        "source_coverage": {
            key: coverage[key] for key in ("source_file_count", "reviewed_source_file_count",
                                           "missing_source_file_count")
        },
        "assessment": assessment,
        "limitations": LIMITATIONS[:],
    }
    issues = validation_errors(report, root, category, catalog, require_safety=False)
    if issues:
        raise ScopeError(f"{category}: 部分報告資料驗證失敗：" + "；".join(issues[:8]))
    return report


def validation_errors(report: Any, root: Path, category: str, catalog: dict[str, Any],
                      *, require_safety: bool = True) -> list[str]:
    """Schema + 規則集合 + 真實來源 + P3 守門；不依賴報告自陳 ready 狀態。"""
    errors: list[str] = []
    try:
        validator = _schema_validator()
        schema_errors = sorted(validator.iter_errors(report),
                               key=lambda e: (list(map(str, e.absolute_path)), e.message))
    except (OSError, ValueError, TypeError, KeyError) as exc:
        return [f"部分報告 Schema 無法載入：{exc}"]
    for issue in schema_errors[:40]:
        location = ".".join(map(str, issue.absolute_path))
        errors.append(f"Schema {location}: {issue.message}")
    if schema_errors:
        return errors
    try:
        expected = _expected(category, catalog)
        assessment = read_category(root, category, catalog)
        snap = _snapshot(root)
        ids = [r["id"] for r in expected]
        checks = report["assessment"]["checks"]
        actual = [c["id"] for c in checks]
        declared = [r["id"] for r in report["rules"]]
        if (report["review_mode"] != "partial" or report["category"] != category
                or report["assessment"]["category"] != category
                or actual != ids or declared != ids):
            errors.append("部分報告只能依固定主檔順序精確涵蓋本分類 ID，不得混入其他分類")
        if any(r["title"] != rule["title"] or r["category"] != category
               for r, rule in zip(report["rules"], expected)):
            errors.append("部分報告規則名稱／分類與正式 rules.json 不一致")
        if report["assessment"] != assessment:
            errors.append("部分報告 assessment 與當前已保存審查證據不一致")
        if (report["source_snapshot_sha256"] != snap["fingerprint"]
                or report["project"]["git_revision"] != snap["git_revision"]
                or assessment["git_revision"] != snap["git_revision"]):
            errors.append("來源快照／Git Revision 不符合當前審查證據")
        if (report["ruleset_version"] != catalog["ruleset_version"]
                or assessment["ruleset_version"] != catalog["ruleset_version"]):
            errors.append("規則版本與正式規則主檔不一致")
        if report["project"] != {key: assessment[key] for key in
                                ("project_id", "git_revision", "assessment_date")}:
            errors.append("專案資訊與分類 assessment 不一致")
        counts = Counter(c["status"] for c in checks)
        expected_summary = {
            "total": len(checks),
            "completed": sum(c["execution"]["state"] == "completed" for c in checks),
            **{status: counts.get(status, 0) for status in STATUSES},
            "findings": len(assessment["findings"]),
        }
        if report["summary"] != expected_summary or expected_summary["completed"] != len(ids):
            errors.append("報告統計與真實逐條審查結果不一致或未完成")
        if report["limitations"] != LIMITATIONS:
            errors.append("不得移除或變造部分審查的必要限制聲明")
        if (assessment.get("scope_details") or {}).get("excluded_paths"):
            errors.append("P4 分類報告不允許未納入來源快照契約的自訂排除目錄")
        coverage = build_source_coverage(assessment, root, selected_categories=(category,))
        actual_coverage = {key: coverage[key] for key in
                           ("source_file_count", "reviewed_source_file_count", "missing_source_file_count")}
        if report["source_coverage"] != actual_coverage:
            errors.append("來源檔案覆蓋統計與目前工作樹不一致")
        if coverage["review_integrity_errors"]:
            errors.extend("逐檔證據：" + note for note in coverage["review_integrity_errors"][:10])
        if coverage["missing_source_file_count"]:
            errors.append(f"尚未完成 {coverage['missing_source_file_count']} 個應審查來源檔")
        errors.extend(_check_source_evidence(root, report, snap))
        allowed = set(ids)
        findings = {f["id"]: f for f in assessment["findings"]}
        if len(findings) != len(assessment["findings"]):
            errors.append("Finding ID 重複")
        for finding in assessment["findings"]:
            if not set(finding["check_ids"]) <= allowed or not finding["check_ids"]:
                errors.append(f"{finding['id']}: Finding 不得引用本分類以外的規則")
        for check in checks:
            if check["status"] != "fail":
                continue
            refs = check.get("finding_ids", [])
            if not refs or any(fid not in findings or check["id"] not in findings[fid]["check_ids"]
                               for fid in refs):
                errors.append(f"{check['id']}: Fail 缺少可查核的本分類 Finding")
        if require_safety:
            if _artifact(root, category, STAGED_FILE).exists():
                errors.append("尚有 staged 交易未整合")
            safety = validate_safety(root, category, catalog)
            if (not safety["safety_valid"] or not safety["first_pass_complete"]
                    or safety["second_pass"]["pending_count"]
                    or safety["safety_integrity_errors"]):
                errors.append("P3 安全及第二輪守門未通過")
                errors.extend(safety["safety_integrity_errors"][:8])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        errors.append(f"部分報告來源或證據校驗失敗：{exc}")
    return errors


def _safe(value: Any) -> str:
    return escape(str(value), quote=True)


def _evidence_markup(evidence: Any) -> str:
    if not isinstance(evidence, list) or not evidence:
        return '<p class="muted">無來源或外部工件佐證。</p>'
    lines = []
    for item in evidence:
        if not isinstance(item, dict):
            continue
        location = item.get("path") or item.get("artifact_id") or "未提供位置"
        if item.get("line_start"):
            location += f":{item['line_start']}-{item.get('line_end', item['line_start'])}"
        lines.append("<li><span class=\"tag\">" + _safe(item.get("kind", "")) + "</span> "
                     + _safe(location) + " — " + _safe(item.get("description", "")) + "</li>")
    return '<ul class="evidence">' + "".join(lines) + "</ul>"


def render_partial_html(data: dict[str, Any]) -> str:
    template = TEMPLATE_PATH.read_text(encoding="utf-8")
    checks = {c["id"]: c for c in data["assessment"]["checks"]}
    rows: list[str] = []
    for rule in data["rules"]:
        check = checks[rule["id"]]
        rid, status = rule["id"], check["status"]
        rows.append(
            '<details id="check-' + _safe(rid) + '"><summary>'
            + _safe(rid) + "　" + _safe(rule["title"]) + "　"
            + '<span class="tag">' + _safe(STATUSES[status]) + "</span></summary>"
            + '<div class="detail"><p><strong>判定理由：</strong>'
            + _safe(check["decision_reason"]) + "</p><p><strong>適用性：</strong>"
            + _safe(check["applicability_reason"]) + "</p><p><strong>已執行檢查：</strong>"
            + _safe((check.get("execution") or {}).get("summary", "")) + "</p></div>"
            + '<h3>追溯證據</h3>' + _evidence_markup(check.get("evidence")) + "</details>"
        )
    findings = []
    for finding in data["assessment"]["findings"]:
        refs = "、".join(finding["check_ids"])
        findings.append(
            '<article class="finding"><h3>' + _safe(finding["id"]) + "　"
            + _safe(finding["title"]) + "　"
            + '<span class="tag">' + _safe(SEVERITIES[finding["severity"]])
            + "</span></h3><p><strong>關聯：</strong>" + _safe(refs)
            + "</p><p><strong>影響：</strong>" + _safe(finding["impact"])
            + "</p><p><strong>建議修改方向：</strong>" + _safe(finding["remediation"])
            + "</p>" + _evidence_markup(finding["evidence"]) + "</article>"
        )
    summary = data["summary"]
    coverage = data["source_coverage"]
    substitutions = {
        "__CATEGORY__": _safe(data["category"]),
        "__PROJECT__": _safe(data["project"]["project_id"]),
        "__DATE__": _safe(data["project"]["assessment_date"]),
        "__REVISION__": _safe(data["project"]["git_revision"]),
        "__SNAPSHOT__": _safe(data["source_snapshot_sha256"]),
        "__TOTAL__": str(summary["total"]),
        "__COMPLETED__": str(summary["completed"]),
        "__PASS__": str(summary["pass"]),
        "__FAIL__": str(summary["fail"]),
        "__REVIEW__": str(summary["review"]),
        "__NA__": str(summary["na"]),
        "__FINDINGS__": str(summary["findings"]),
        "__SOURCE_TOTAL__": str(coverage["source_file_count"]),
        "__SOURCE_REVIEWED__": str(coverage["reviewed_source_file_count"]),
        "__SOURCE_MISSING__": str(coverage["missing_source_file_count"]),
        "__CHECK_ITEMS__": "\n".join(rows),
        "__FINDING_ITEMS__": "\n".join(findings) if findings else '<p class="muted">本分類未記錄 Finding。</p>',
        "__LIMITATION_ITEMS__": "".join("<li>" + _safe(s) + "</li>" for s in data["limitations"]),
    }
    for marker, value in substitutions.items():
        if marker not in template:
            raise ScopeError(f"部分報告模板缺少必要佔位符：{marker}")
        template = template.replace(marker, value)
    return render_html(template, data)


def html_errors(html: str, report: dict[str, Any]) -> list[str]:
    errors = []
    try:
        extracted, parsed = extract_html_report(html)
        if extracted != report:
            errors.append("HTML 內嵌 JSON 與 report.json 不一致")
        if parsed.external_assets:
            errors.extend("HTML 包含不安全外部資源：" + entry for entry in parsed.external_assets)
        mandatory = {"report-data", "scope", "checks", "findings", "limits"}
        if not mandatory <= set(parsed.ids):
            errors.append("HTML 缺少部分審查必要節點")
        if html != render_partial_html(report):
            errors.append("HTML 與固定部分審查模板及 JSON 不一致")
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        errors.append(f"HTML 驗證失敗：{exc}")
    return errors


def _html_path(root: Path, category: str, assessment: dict) -> Path:
    date = assessment["assessment_date"]
    return _artifact(root, category, f"CodeReview_{date.replace('-', '')}.html")


def complete(root: Path, categories: tuple[str, ...], catalog: dict[str, Any]) -> list[dict[str, Any]]:
    """先驗證全部指定分類，再開始寫入，避免 A 成功但 B 不合法造成半批更新。"""
    build_scope_plan(root, categories, catalog)
    planned = []
    for category in categories:
        data = build_report(root, category, catalog)
        html = render_partial_html(data)
        issues = html_errors(html, data)
        if issues:
            raise ScopeError(f"{category}: " + "；".join(issues[:8]))
        json_path = _artifact(root, category, REPORT_FILE)
        html_path = _html_path(root, category, data["assessment"])
        if json_path == html_path or json_path.name == "assessment.json":
            raise ScopeError("分類報告輸出位置與原始證據衝突")
        planned.append((category, data, html, json_path, html_path))
    # 寫入前二次來源快照核對；防止資料建立至輸出之間發生來源變更。
    for category, data, _, _, _ in planned:
        issues = validation_errors(data, root, category, catalog)
        if issues:
            raise ScopeError(f"{category}: 寫入前重新驗證失敗：" + "；".join(issues[:8]))
    output = []
    for category, data, html, json_path, html_path in planned:
        _atomic(json_path, data)
        # HTML 也使用安全的原子替換；失敗的驗證不會寫入任何報告。
        _atomic_html(html_path, html)
        output.append({"category": category, "report_path": str(json_path),
                       "html_path": str(html_path), "rule_count": len(data["rules"])})
    return output


def _atomic_html(path: Path, html: str) -> None:
    import os
    import tempfile
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".partial-html-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(html)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def validate_saved(root: Path, categories: tuple[str, ...], catalog: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    build_scope_plan(root, categories, catalog)
    for category in categories:
        try:
            assessment = read_category(root, category, catalog)
            report_path = _artifact(root, category, REPORT_FILE)
            html_path = _html_path(root, category, assessment)
            if not report_path.is_file() or not html_path.is_file():
                errors.append(f"{category}: 尚未產生完整的分類 report.json / HTML")
                continue
            data = json.loads(report_path.read_text(encoding="utf-8"))
            html = html_path.read_text(encoding="utf-8")
            errors.extend(f"{category}: {item}" for item in
                          validation_errors(data, root, category, catalog))
            if isinstance(data, dict):
                errors.extend(f"{category}: {item}" for item in html_errors(html, data))
        except (ScopeError, OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"{category}: 報告驗證失敗：{exc}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="產生／驗證逐分類的 HTML、JSON 報告；保留正式 70 項報告")
    parser.add_argument("--target", type=Path, default=Path.cwd(), help="受測專案根目錄")
    parser.add_argument("--categories", action="append", required=True, metavar="AC,AU")
    parser.add_argument("--validate-only", action="store_true", help="僅核對已產生的部分報告")
    args = parser.parse_args(argv)
    if len(args.categories) != 1:
        parser.error("--categories 只能提供一次")
    try:
        root = args.target.resolve()
        cats = parse_categories(args.categories[0])
        catalog = load_catalog()
        if args.validate_only:
            problems = validate_saved(root, cats, catalog)
            for issue in problems:
                print("ERROR:", issue, file=sys.stderr)
            if problems:
                return 1
            print(f"PASS: {len(cats)} 個分類部分 HTML/JSON、來源與安全證據均驗證通過")
        else:
            results = complete(root, cats, catalog)
            problems = validate_saved(root, cats, catalog)
            if problems:
                for issue in problems:
                    print("ERROR:", issue, file=sys.stderr)
                return 1
            print(json.dumps({"review_mode": "partial", "reports": results,
                              "validated": True, "formal_70_rule_review": False},
                             ensure_ascii=False, indent=2))
        return 0
    except (ScopeError, OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print("ERROR:", exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
