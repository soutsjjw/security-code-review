#!/usr/bin/env python3
"""提供 Codex 可重複查詢的 70 項審查佇列，不自行推斷安全結論。"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from datetime import date
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parents[1]
REPORT_RELATIVE = Path("reports/security-code-review")


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


def build_queue(data: dict, rules: list[dict], batch_size: int) -> dict:
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
    remaining = [r for r in rules if (indexed[r["id"]].get("execution") or {}).get("state") != "completed"]
    selected = remaining[:batch_size]
    return {
        "total": 70,
        "completed": states.get("completed", 0),
        "pending": states.get("pending", 0),
        "blocked": states.get("blocked", 0),
        "findings_saved": len(data.get("findings", [])),
        "ready_for_report": len(remaining) == 0,
        "remaining_ids": [r["id"] for r in remaining],
        "next_checks": [{
            "id": r["id"],
            "title": r["title"],
            "current_state": (indexed[r["id"]].get("execution") or {}).get("state", "pending"),
            "search_targets": r.get("inspection", {}).get("search_targets", []),
            "inspection_hints": r.get("inspection", {}).get("legacy_inspection_hints", []),
            "verification_method": r.get("inspection", {}).get("verification_method", ""),
            "applicable_when": r.get("applicability", {}).get("must_assess_when", ""),
            "na_when": r.get("applicability", {}).get("may_be_not_applicable_when", "")
        } for r in selected],
        "instruction": ("已完成全部 70 項，執行 complete_review.py 並驗證 HTML/JSON。"
                        if not remaining else
                        "對 next_checks 逐項實際分析並更新 assessment.json；找到漏洞要記錄 Finding，"
                        "不得修復受測程式或提前結束。儲存後再次執行此工具取得下一批。")
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="查詢與初始化 70 項審查待辦佇列")
    parser.add_argument("--target", type=Path, default=Path.cwd())
    parser.add_argument("--init", action="store_true", help="僅建立不存在的審查檔；保留既有結果")
    parser.add_argument("--batch-size", type=int, default=10)
    args = parser.parse_args()
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
        queue = build_queue(payload, rules, args.batch_size)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    print(json.dumps(queue, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
