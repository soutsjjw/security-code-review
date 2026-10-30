#!/usr/bin/env python3
"""由 rules.json 產生 docs/70-rules-standardized.md；--check 確認文件未與規則主檔脫節。

Markdown 只是規則主檔的閱讀版本，任何規則內容修改都應改 rules.json 後重新產生。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MASTER = ROOT / "rules.json"
OUTPUT = ROOT / "docs/70-rules-standardized.md"
RELEASE_LABELS = {"stable": "正式版"}

COMMON_CRITERIA = """## 共通判定準則

- **Pass／符合**：適用要求已以實證完成；僅靠找不到問題、關鍵字未命中或理論設計不足以判符合。
- **Fail／不符合**：適用條件成立、存在可驗證不符且已評估部署層或外部等效控制。
- **Review／待確認**：缺少完整程式碼、部署、測試、營運或政策證據。
- **N/A／不適用**：確定功能及相關義務均不適用，需逐項記錄具體理由。
- 風險高低由實際影響面評估，不以 Fail 項數或檢核類別推定。
- 法定例外／免執行不等於 N/A；應另有核准、風險接受及法定程序紀錄。
"""


def _rule(rule: dict) -> str:
    refs = rule["references"]
    asvs = ", ".join(r["requirement_id"] for r in refs["technical_requirements"]) or "待正式逐條核對"
    owasp = ", ".join(r["category_id"] for r in refs.get("risk_taxonomy") or []) or "不強制對應"
    fields = [
        ("控制目標", rule["control_objective"]),
        ("適用", rule["applicability"]["must_assess_when"]),
        ("不適用前提", rule["applicability"]["may_be_not_applicable_when"]),
        ("審查重點", "；".join(rule["inspection"]["search_targets"])),
        ("符合（Pass）", rule["assessment"]["pass"]),
        ("不符合（Fail）", rule["assessment"]["fail"]),
        ("待確認（Review）", rule["assessment"]["review"]),
        ("證據要求", rule["evidence_requirements"]["what_to_collect"]),
        ("人工確認", rule["manual_review"]),
        ("改善方向", rule["remediation_guidance"]),
        ("判定注意", rule["normative_notes"]),
        ("ASVS 5.0.0 對應", f"{asvs}（已列項為相關要求，非完整等價）"),
        ("OWASP 2025 風險分類", f"{owasp}（建議分類，非合規要求）"),
    ]
    body = "\n".join(f"- **{label}**：{value}" for label, value in fields)
    return f"### {rule['id']} {rule['title']}\n\n{body}\n"


def render(catalog: dict) -> str:
    by_id = {rule["id"]: rule for rule in catalog["rules"]}
    release = RELEASE_LABELS.get(catalog["release_status"], catalog["release_status"])
    parts = [
        "<!-- 由 scripts/render_rules_markdown.py 自 rules.json 產生，請勿手動修改。 -->\n"
        "# 跨系統原始碼資安檢核 — 70 項標準化規則\n",
        f"> 規則版本：**{catalog['ruleset_version']} {release}** ｜原始整理日期：{catalog['prepared_date']} "
        f"｜發布日期：{catalog['release_date']} ｜狀態：**{catalog['release_status']}（不以公司資安核定作為版本發布門檻）**\n"
        "> 說明：保留 70 項規則編號與名稱作為跨系統共用基準；**不包含任何特定系統的評分或審查結果**。"
        "本文件中的判定條件為公司基線提案，非原始法規逐字重製。\n",
        "## 總覽\n\n| 類別 | 項數 | 範圍 |\n|---|---:|---|\n" + "".join(
            f"| {c['code']} — {c['name']} | {len(c['rule_ids'])} | {c['rule_ids'][0]}～{c['rule_ids'][-1]} |\n"
            for c in catalog["categories"]),
        COMMON_CRITERIA,
        "## 70 項逐條定義\n",
    ]
    for category in catalog["categories"]:
        parts.append(f"## {category['code']}：{category['name']}\n")
        parts.extend(_rule(by_id[rid]) for rid in category["rule_ids"])
    return "\n".join(parts) + "\n"


def markdown_errors(root: Path = ROOT) -> list[str]:
    output = root / OUTPUT.relative_to(ROOT)
    catalog = json.loads((root / MASTER.relative_to(ROOT)).read_text(encoding="utf-8"))
    if not output.is_file():
        return [f"{OUTPUT.name} missing"]
    if output.read_text(encoding="utf-8") != render(catalog):
        return [f"{OUTPUT.name} is out of sync with rules.json; run scripts/render_rules_markdown.py --write"]
    return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="由 rules.json 重新產生文件")
    mode.add_argument("--check", action="store_true", help="確認文件與 rules.json 一致")
    args = parser.parse_args(argv)
    if args.write:
        catalog = json.loads(MASTER.read_text(encoding="utf-8"))
        OUTPUT.write_bytes(render(catalog).encode("utf-8"))
        print(f"wrote {OUTPUT.relative_to(ROOT).as_posix()}")
        return 0
    errors = markdown_errors()
    for error in errors:
        print("ERROR:", error, file=sys.stderr)
    if not errors:
        print(f"PASS: {OUTPUT.name} matches rules.json")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
