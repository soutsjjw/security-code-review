#!/usr/bin/env python3
"""解析完整／分類審查範圍並規劃隔離路徑；本工具不執行審查或寫入資料。

分類審查的佇列、驗證及報告流程尚未接通前，不可將本計畫當作完成紀錄。
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import sys
from typing import Any

SKILL_ROOT = Path(__file__).resolve().parents[1]
RULES_FILE = SKILL_ROOT / "rules.json"
REPORT_ROOT = Path("reports/security-code-review")
PARTIAL_ROOT = REPORT_ROOT / "partial"
CATEGORY_COUNTS = {
    "AC": 8, "AU": 10, "IN": 8, "CR": 6, "EH": 6,
    "LG": 10, "DP": 4, "PD": 8, "BC": 7, "SI": 3,
}
CATEGORIES = tuple(CATEGORY_COUNTS)


class ScopeError(ValueError):
    """拒絕不明確的分類或無效的規則主檔。"""


def parse_categories(raw: str | None) -> tuple[str, ...] | None:
    """None 代表完整審查；明確提供 --categories 時至少需要一個合法分類。"""
    if raw is None:
        return None
    parts = [item.strip().upper() for item in raw.split(",")]
    if not parts or any(not part for part in parts):
        raise ScopeError("--categories 不得為空，且分類之間不得有空白項目")
    invalid = sorted(set(parts) - set(CATEGORIES))
    if invalid:
        raise ScopeError(f"未知分類：{', '.join(invalid)}；允許：{', '.join(CATEGORIES)}")
    if len(parts) != len(set(parts)):
        raise ScopeError("--categories 不得包含重複分類")
    # 使用規則主檔的固定分類順序，避免不同輸入順序產生不同計畫。
    return tuple(category for category in CATEGORIES if category in parts)


def validate_catalog(ruleset: Any) -> list[dict[str, Any]]:
    """分類選擇只能來自原有完整 70 項規則主檔，不得使用替代子集。"""
    if not isinstance(ruleset, dict) or not isinstance(ruleset.get("rules"), list):
        raise ScopeError("規則主檔缺少 rules 陣列")
    rules = ruleset["rules"]
    if len(rules) != 70:
        raise ScopeError("規則主檔必須包含全部 70 項")
    ids: set[str] = set()
    counts: Counter[str] = Counter()
    for rule in rules:
        if not isinstance(rule, dict):
            raise ScopeError("規則主檔含有非物件規則")
        rid, cat = rule.get("id"), rule.get("category")
        if (not isinstance(rid, str) or not isinstance(cat, str)
                or cat not in CATEGORY_COUNTS or not rid.startswith(cat + "-")
                or len(rid) != len(cat) + 3 or not rid[-2:].isdigit()):
            raise ScopeError(f"無效的規則 ID／分類對應：{rid!r}／{cat!r}")
        if rid in ids:
            raise ScopeError(f"規則 ID 重複：{rid}")
        ids.add(rid)
        counts[cat] += 1
    if dict(counts) != CATEGORY_COUNTS:
        raise ScopeError(f"規則分類數量與正式 70 項不符：{dict(counts)}")
    return rules


def load_catalog() -> dict[str, Any]:
    try:
        return json.loads(RULES_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ScopeError(f"無法載入完整規則主檔：{exc}") from exc


def build_scope_plan(target: Path, categories: tuple[str, ...] | None,
                     ruleset: dict[str, Any]) -> dict[str, Any]:
    """純讀取並回傳穩定的相對路徑；不建立資料夾／審查狀態。"""
    root = target.resolve()
    if not root.is_dir() or root == SKILL_ROOT or SKILL_ROOT in root.parents:
        raise ScopeError("受測路徑不存在或指向 Skill 安裝目錄")
    rules = validate_catalog(ruleset)
    if categories is not None:
        if not categories or len(categories) != len(set(categories)) or any(
            cat not in CATEGORY_COUNTS for cat in categories
        ):
            raise ScopeError("分類集合不合法，請使用 parse_categories 建立")
        # 程式化呼叫同樣標準化順序。
        categories = tuple(cat for cat in CATEGORIES if cat in categories)

    partial = categories is not None
    selected_categories = categories if partial else CATEGORIES
    included = set(selected_categories)
    selected_rules = [rule for rule in rules if rule["category"] in included]
    ids_by_category = {
        category: [rule["id"] for rule in rules if rule["category"] == category]
        for category in selected_categories
    }
    category_reports = []
    if partial:
        for category in selected_categories:
            directory = PARTIAL_ROOT / category
            category_reports.append({
                "category": category,
                "expected_rule_count": len(ids_by_category[category]),
                "rule_ids": ids_by_category[category],
                "report_dir": directory.as_posix(),
                "assessment_path": (directory / "assessment.json").as_posix(),
                "project_path": (directory / "project.json").as_posix(),
                "report_path": (directory / "report.json").as_posix(),
                "analysis_dir": (directory / "analysis").as_posix(),
                "html_filename_pattern": "CodeReview_YYYYMMDD.html",
            })
    return {
        "scope_plan_version": 1,
        "review_mode": "partial" if partial else "full",
        "target_root": str(root),
        "ruleset_version": ruleset.get("ruleset_version"),
        "catalog_rule_count": 70,
        "selected_categories": list(selected_categories),
        "selected_rule_count": len(selected_rules),
        "selected_rule_ids": [rule["id"] for rule in selected_rules],
        "formal_report_dir": REPORT_ROOT.as_posix(),
        "shared_analysis_dir": (PARTIAL_ROOT / "_shared" / "analysis").as_posix()
        if partial else (REPORT_ROOT / "analysis").as_posix(),
        "category_reports": category_reports,
        "plan_only": True,
        "notice": "僅完成審查範圍及路徑規劃；尚未執行分類審查、驗證或報告。",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="預先驗證分類與輸出路徑（唯讀，不開始資安審查）")
    parser.add_argument("--target", type=Path, default=Path.cwd(), help="受測專案根目錄")
    parser.add_argument("--categories", metavar="AC,AU", help="指定 1～10 個分類；不指定則為完整 70 項")
    args = parser.parse_args(argv)
    try:
        categories = parse_categories(args.categories)
        plan = build_scope_plan(args.target, categories, load_catalog())
    except ScopeError as exc:
        parser.error(str(exc))
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    print(json.dumps(plan, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
