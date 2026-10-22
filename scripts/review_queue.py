#!/usr/bin/env python3
"""提供 Codex 可重複查詢的 70 項審查佇列，不自行推斷安全結論。"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import yaml
from system_baseline import source_review_hints
from web_guide import web_guide_review_hints
from web_appendix1 import appendix_review_hints
from web_headers import header_review_hints
from collections import Counter
from datetime import date
from pathlib import Path
from source_coverage import build_source_coverage
from review_completion import completion_errors
from analysis_candidates import candidate_hits
from source_reader import read_source_text

SKILL_ROOT = Path(__file__).resolve().parents[1]
REPORT_RELATIVE = Path("reports/security-code-review")
TACERT_V2_FILE = SKILL_ROOT / "standards" / "tacert-v2-checklist.yaml"
OWASP_2025_FILE = SKILL_ROOT / "standards" / "owasp-top10-2025.yaml"


def load_owasp_2025_categories(rules: list[dict]) -> dict[str, list[dict]]:
    """將 OWASP Top 10:2025 官方分類對應至 70 項規則（非符合判定）。"""
    document = yaml.safe_load(OWASP_2025_FILE.read_text(encoding="utf-8"))
    mapped = {rule["id"]: [] for rule in rules}
    for category in document["categories"]:
        for rid in category["related_rule_ids"]:
            if rid not in mapped:
                raise ValueError(f"OWASP 2025 分類對應未知規則：{rid}")
            mapped[rid].append({
                "id": category["id"],
                "title": category["title"],
                "review_steps": category["review_steps"],
                "coverage_gap": category["coverage_gap"],
                "source_url": category["url"],
                "mapping_type": category["mapping_type"],
            })
    return mapped


def load_tacert_v2_checks(rules: list[dict]) -> dict[str, list[dict]]:
    """將 TACERT V2 各補充要求掛到既有規則；不變更 70 項身分與進度模型。"""
    data = yaml.safe_load(TACERT_V2_FILE.read_text(encoding="utf-8"))
    mapped = {rule["id"]: [] for rule in rules}
    for entry in data["checks"]:
        for rid in entry["related_rule_ids"]:
            if rid not in mapped:
                raise ValueError(f"TACERT V2 檢核對應未知規則：{rid}")
            mapped[rid].append({
                "id": entry["id"], "title": entry["title"],
                "pdf_page": entry["pdf_page"],
                "verification_mode": entry["verification_mode"],
                "review_steps": entry["review_steps"],
                "expected_evidence": entry["expected_evidence"],
            })
    return mapped


def load_rules() -> tuple[dict, list[dict]]:
    data = json.loads((SKILL_ROOT / "rules.json").read_text(encoding="utf-8"))
    rules = data["rules"]
    if len(rules) != 70 or len({r["id"] for r in rules}) != 70:
        raise ValueError("規則主檔必須包含 70 項不重複檢核")
    return data, rules


def initialize(target: Path, report_dir: Path, ruleset: dict, rules: list[dict]) -> None:
    """只建立不存在的檔案；絕不覆寫既有審查、Finding 或人工設定。"""
    assessment_path = report_dir / "assessment.json"
    project_path = report_dir / "project.json"
    if assessment_path.is_file() and project_path.is_file():
        return
    report_dir.mkdir(parents=True, exist_ok=True)
    if not assessment_path.exists():
        revision = subprocess.run(
            ["git", "-C", str(target), "rev-parse", "HEAD"],
            text=True, capture_output=True, check=False
        )
        git_revision = revision.stdout.strip() if revision.returncode == 0 else "not-a-git-repository"
        assessment = {
            "ruleset_version": ruleset["ruleset_version"],
            "project_id": target.name,
            "git_revision": git_revision,
            "assessment_date": date.today().isoformat(),
            "scope": "受測專案全部原始碼，需由 Codex 逐項核對",
            "checks": [{
                "id": rule["id"],
                "status": "review",
                "applicability_reason": "待分析功能與控制責任是否適用",
                "decision_reason": "尚未執行審查與佐證核對",
                "evidence": [],
                "reviewer": "security-code-review-agent",
                "execution": {
                    "state": "pending",
                    "methods": [],
                    "summary": "尚未執行審查，必須進行規則核對"
                }
            } for rule in rules],
            "findings": []
        }
        assessment_path.write_text(json.dumps(assessment, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if not project_path.exists():
        project = {"name": target.name, "language_framework": "待實際盤點"}
        project_path.write_text(json.dumps(project, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def build_queue(data: dict, rules: list[dict], batch_size: int, *, source_root: Path | None = None,
                compact: bool = False, detail_id: str | None = None) -> dict:
    checks = data.get("checks")
    if not isinstance(checks, list):
        raise ValueError("assessment.json 缺少 checks 陣列")
    indexed = {c["id"]: c for c in checks}
    master_ids = {r["id"] for r in rules}
    if len(indexed) != 70 or len(checks) != 70 or set(indexed) != master_ids:
        raise ValueError("assessment.json 的 checks 必須完整且不重複涵蓋 70 項")
    states = Counter((c.get("execution") or {}).get("state", "pending") for c in checks)
    illegal = sorted(set(states) - {"pending", "completed", "blocked"})
    if illegal:
        raise ValueError("無效執行狀態：" + ", ".join(illegal))
    tacert_by_rule = load_tacert_v2_checks(rules)
    owasp_by_rule = load_owasp_2025_categories(rules)
    system_baseline_by_rule = source_review_hints(rules)
    web_guide_by_rule = web_guide_review_hints(rules)
    web_appendix_by_rule = appendix_review_hints(rules)
    web_headers_by_rule = header_review_hints(rules)
    remaining = [r for r in rules if (indexed[r["id"]].get("execution") or {}).get("state") != "completed"]
    if detail_id is not None and detail_id not in master_ids:
        raise ValueError(f"未知規則 ID：{detail_id}")
    selected = ([next(r for r in rules if r["id"] == detail_id)]
                if detail_id is not None else remaining[:batch_size])
    coverage = build_source_coverage(data, source_root) if source_root is not None else None
    unreviewed = coverage["missing_source_file_count"] if coverage else 0
    integrity_errors = coverage["review_integrity_errors"] if coverage else []
    # 顯示下一批檔案的多條規則候選，協助 Agent 追查；候選不能自動算 completed。
    source_candidates = []
    if coverage and source_root is not None:
        for path in coverage["missing_source_paths"][:30]:
            try:
                hits = candidate_hits(path, read_source_text(source_root / path)[0])
            except (OSError, UnicodeError):
                continue
            if hits:
                source_candidates.append({
                    "path": path, "rule_ids": [hit["rule_id"] for hit in hits],
                })
            if len(source_candidates) >= 15:
                break
    rule_errors = completion_errors(checks) if not remaining else []
    # 70/70 完成但證據品質不合格時，原佇列 next_checks 為空，Agent 容易停止。
    # 從來源完整性／規則完整性錯誤抽取須重新核對的真實規則，不變更原始狀態。
    ids_to_recheck: set[str] = set()
    for diagnostic in [*integrity_errors, *rule_errors]:
        ids_to_recheck.update(
            match for match in re.findall(r"\b(?:AC|AU|IN|CR|EH|LG|DP|PD|BC|SI)-\d{2}\b", diagnostic)
            if match in master_ids
        )
    if not remaining and ids_to_recheck and detail_id is None:
        selected = [rule for rule in rules if rule["id"] in ids_to_recheck][:batch_size]
    queue = {
        "total": 70,
        "tacert_v2_supplemental_items": 39,
        "owasp_top10_2025_categories": 10,
        "system_baseline_v13_controls": 80,
        "web_guide_v32_categories": 29,
        "web_guide_v32_implementation_topics": 35,
        "web_guide_v32_appendix1_checks": 55,
        "web_guide_v32_appendix3_headers": 6,
        "completed": states.get("completed", 0),
        "pending": states.get("pending", 0),
        "blocked": states.get("blocked", 0),
        "findings_saved": len(data.get("findings", [])),
        "ready_for_report": (source_root is not None and len(remaining) == 0 and unreviewed == 0
                             and not integrity_errors and not rule_errors),
        "source_coverage": ({
            "source_file_count": coverage["source_file_count"],
            "reviewed_source_file_count": coverage["reviewed_source_file_count"],
            "missing_source_file_count": unreviewed,
            "missing_by_type": coverage["missing_by_type"],
        } if coverage else None),
        "next_source_paths": coverage["missing_source_paths"][:30] if coverage else [],
        "next_source_candidates": source_candidates,
        "review_integrity_errors": integrity_errors[:20],
        "rule_integrity_errors": rule_errors[:30],
        "remaining_ids": [r["id"] for r in remaining],
        "recheck_rule_ids": sorted(ids_to_recheck),
        "recheck_reason_count": len(integrity_errors) + len(rule_errors),
        "next_checks": [{
            "id": r["id"],
            "title": r["title"],
            "current_state": (indexed[r["id"]].get("execution") or {}).get("state", "pending"),
            "search_targets": r.get("inspection", {}).get("search_targets", []),
            "inspection_hints": r.get("inspection", {}).get("legacy_inspection_hints", []),
            "verification_method": r.get("inspection", {}).get("verification_method", ""),
            "applicable_when": r.get("applicability", {}).get("must_assess_when", ""),
            "na_when": r.get("applicability", {}).get("may_be_not_applicable_when", ""),
            "tacert_v2_checks": tacert_by_rule[r["id"]],
            "owasp_2025_categories": owasp_by_rule[r["id"]],
            "system_baseline_v13_controls": system_baseline_by_rule[r["id"]],
            "web_guide_v32_checks": web_guide_by_rule[r["id"]],
            "web_guide_v32_appendix1": web_appendix_by_rule[r["id"]],
            "web_guide_v32_appendix3": web_headers_by_rule[r["id"]]
        } for r in selected],
        "instruction": ("70 項雖已標記 completed，但仍有規則證據或判定品質不足：" +
                        "；".join(rule_errors[:3]) +
                        "。須重新檢查規則與來源，不得僅補 JSON／模板字串。"
                        if not remaining and rule_errors else
                        "正式報告需要指定真實受測來源目錄與完整逐檔證據。"
                        if not remaining and source_root is None else
                        "逐檔規則適用性或來源佐證不完整，先修復 file_reviews 中的問題，" +
                        "重新核對實際原始碼與 execution.inspected_paths；不得僅增加檢核 ID。"
                        if not remaining and integrity_errors else
                        "70 項規則狀態已完成，但仍有 " + str(unreviewed) +
                        " 個應審查原始碼／設定檔未曾列入 completed 的 inspected_paths；"
                        "先逐檔實際閱讀 next_source_paths 並補查相關規則，再更新紀錄，不可直接產生最終報告。"
                        if not remaining and unreviewed else
                        "已完成全部 70 項及應審查原始碼覆蓋，執行 complete_review.py 並驗證 HTML/JSON。"
                        if not remaining else
                        "對 next_checks 逐項實際分析並更新 assessment.json；找到漏洞要記錄 Finding，"
                        "逐項納入 tacert_v2_checks 與 owasp_2025_categories 的可驗證內容，未覆蓋的 coverage_gap 與缺少部署/動態佐證時清楚記錄待確認；system_baseline_v13_controls 是獨立普／中／高防護基準提示，不得從原 70 項狀態自動宣稱已符合；web_guide_v32_checks 依 V3.2 第4章查核 ASP.NET/.NET 及通用 Web 控制，不執行 Java、PHP 專屬範例或規則，缺外部證據記待確認；web_guide_v32_appendix1 為附件1 55項逐列檢測提示：適用項目可依源碼與外部證據單獨記錄，不得以70項 Pass 自動宣稱附件符合；web_guide_v32_appendix3 補強 CR-05 六項 HTTP 安全標頭、HSTS 與 CR-01、CSP 與 IN-02 的關聯；只能採 ASP.NET/.NET 或通用 HTTP 控制，Java/PHP 專屬範例排除；缺真實 HTTPS 回應證據不得標 pass，需記錄各個標頭實際安全設定值與部署限制；不得修復受測程式或提前結束。儲存後再次執行此工具取得下一批。")
    }
    if compact:
        # 唯一目的：減少送入 AI 上下文的佇列字數；詳細規範請用 --detail-id。
        queue["next_checks"] = [{
            "id": r["id"], "title": r["title"],
            "current_state": (indexed[r["id"]].get("execution") or {}).get("state", "pending"),
            "search_targets": r.get("inspection", {}).get("search_targets", []),
        } for r in selected]
        if remaining:
            queue["instruction"] = ("以本機分析索引定位來源與呼叫鏈；每條規則須真實查核，"
                                    "需要詳細規範時使用 --detail-id <規則ID>。逐檔紀錄與 Finding 仍不可省略。")
        elif ids_to_recheck:
            queue["instruction"] = (
                "70 項執行紀錄雖已 completed，仍有實際程式碼證據／適用性檢查失敗。"
                "請依 recheck_rule_ids、next_checks 與 next_source_paths 重新核實，"
                "保留既有 Findings，不得只改寫判定理由或自動改成 Pass。"
            )
    return queue


def main() -> int:
    parser = argparse.ArgumentParser(description="查詢與初始化 70 項審查待辦佇列")
    parser.add_argument("--target", type=Path, default=Path.cwd())
    parser.add_argument("--init", action="store_true", help="僅建立不存在的審查檔；保留既有結果")
    parser.add_argument("--batch-size", type=int, default=10)
    parser.add_argument("--compact", action="store_true", help="僅回傳精簡檢核工作清單；詳細規範另查")
    parser.add_argument("--detail-id", help="僅查詢一條規則的詳細提示（包括已完成規則）")
    args = parser.parse_args()
    if args.compact and args.detail_id:
        parser.error("--compact 與 --detail-id 不可同時指定")
    if not 1 <= args.batch_size <= 70:
        parser.error("--batch-size 必須介於 1 到 70")
    target = args.target.resolve()
    if not target.is_dir() or target == SKILL_ROOT or SKILL_ROOT in target.parents:
        parser.error("受測路徑不存在或指向 Skill 安裝目錄")
    out = target / REPORT_RELATIVE
    try:
        ruleset, rules = load_rules()
        if args.init:
            initialize(target, out, ruleset, rules)
        path = out / "assessment.json"
        if not path.is_file():
            raise FileNotFoundError(f"尚未建立 {path}；請使用 --init")
        payload = json.loads(path.read_text(encoding="utf-8"))
        queue = build_queue(payload, rules, args.batch_size, source_root=target,
                            compact=args.compact, detail_id=args.detail_id)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    print(json.dumps(queue, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
