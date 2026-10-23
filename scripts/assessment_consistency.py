#!/usr/bin/env python3
"""assessment 內部一致性檢查：Finding 與檢核狀態連動、判定理由矛盾、佔位字、review 比例。

這是保守的機械檢查，不判斷安全結論是否正確；只攔截資料自相矛盾的情況。
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

# 「保留 review」「故為 review」等語句出現在 pass／fail 的判定理由中，代表狀態與理由不一致。
STATUS_CONTRADICTION = re.compile(r"(保留|維持|仍為|故為|列為|沿用|仍屬)\s*[`'\"「]?\s*review", re.IGNORECASE)
PLACEHOLDER_VALUES = ("待實際盤點", "未能自動辨識")
REVIEW_KIND_STATIC = "static_done_external_pending"
REVIEW_KIND_EXTERNAL = "external_only"
REVIEW_RATIO_WARN = 0.7
_SKIP_DIRS = {".git", "bin", "obj", "node_modules", "reports", ".vs", ".codegraph",
              ".code-review-graph", ".understand-anything", ".security-review-venv"}


def consistency_errors(data: dict[str, Any]) -> list[str]:
    """回傳必須修正的矛盾；不改寫資料。"""
    errors: list[str] = []
    checks = {c.get("id"): c for c in data.get("checks", []) if isinstance(c, dict)}
    for check in checks.values():
        status = check.get("status")
        reason = str(check.get("decision_reason", ""))
        if status in ("fail", "pass") and STATUS_CONTRADICTION.search(reason):
            errors.append(f"{check.get('id')}: status={status}，但 decision_reason 仍寫保留 review，狀態與理由不一致")
    for finding in data.get("findings", []):
        if not isinstance(finding, dict) or finding.get("confidence") != "confirmed":
            continue
        linked = [checks[i] for i in finding.get("check_ids", []) if i in checks]
        if not linked:
            continue
        passed = [c["id"] for c in linked if c.get("status") == "pass"]
        if passed:
            errors.append(f"{finding.get('id')}: 已確認 Finding 關聯的檢核 {'、'.join(passed)} 卻為 pass")
        if not any(c.get("status") == "fail" for c in linked):
            states = "、".join(f"{c['id']}={c.get('status')}" for c in linked)
            errors.append(
                f"{finding.get('id')}: 信心為 confirmed，但關聯檢核（{states}）無一為 fail；"
                "靜態證據已證實弱點時，至少一個主要關聯規則必須記 fail")
    return errors


def review_ratio(data: dict[str, Any]) -> tuple[int, int]:
    checks = [c for c in data.get("checks", []) if isinstance(c, dict)]
    return sum(c.get("status") == "review" for c in checks), len(checks)


def review_breakdown(checks: list[dict[str, Any]]) -> dict[str, int]:
    review = [c for c in checks if c.get("status") == "review"]
    return {
        "static": sum(c.get("review_kind") == REVIEW_KIND_STATIC for c in review),
        "external": sum(c.get("review_kind") == REVIEW_KIND_EXTERNAL for c in review),
        "unclassified": sum(c.get("review_kind") not in (REVIEW_KIND_STATIC, REVIEW_KIND_EXTERNAL) for c in review),
    }


def consistency_warnings(data: dict[str, Any]) -> list[str]:
    review, total = review_ratio(data)
    if total and review / total > REVIEW_RATIO_WARN:
        return [f"review 占 {review}/{total}（{review * 100 // total}%），超過 {int(REVIEW_RATIO_WARN * 100)}% 警示門檻；"
                "請逐項確認靜態可判定者是否應記 pass／fail，並於 presentation.review_ratio_explanation 說明"]
    return []


def project_placeholder_errors(project: dict[str, Any]) -> list[str]:
    value = str(project.get("language_framework", "")).strip()
    if not value or any(p in value for p in PLACEHOLDER_VALUES):
        return [f"project.json 的 language_framework 仍是佔位值（{value or '空白'}）；請依實際 .csproj 盤點填寫"]
    return []


def detect_language_framework(target: Path) -> str:
    """從 .csproj／Directory.Build.props 唯讀推得框架；失敗回傳佔位值，由驗證擋下。"""
    frameworks: set[str] = set()
    is_web = False
    scanned = 0
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in files:
            if not (name.endswith(".csproj") or name == "Directory.Build.props"):
                continue
            scanned += 1
            try:
                text = (Path(root) / name).read_text(encoding="utf-8-sig", errors="replace")
            except OSError:
                continue
            for m in re.finditer(r"<TargetFrameworks?>\s*([^<]+?)\s*</TargetFrameworks?>", text):
                frameworks.update(x.strip() for x in m.group(1).split(";") if x.strip())
            is_web = is_web or 'Sdk="Microsoft.NET.Sdk.Web"' in text
        if scanned > 500:
            break
    if not frameworks:
        return PLACEHOLDER_VALUES[1] + "（Agent 須依實際盤點填寫）"
    kind = "ASP.NET Core" if is_web else ".NET"
    return f"{kind}（C#，{'、'.join(sorted(frameworks))}）"


def clip_text(text: str, limit: int) -> str:
    """在句讀邊界截斷，避免把詞或句子切成半截；仍超長時加「…」。"""
    text = " ".join(str(text).split())
    if len(text) <= limit:
        return text
    head = text[:limit]
    cut = max(head.rfind(c) for c in "。；;，,、")
    if cut >= limit // 2:
        return head[:cut].rstrip("，,、；;") + "…"
    return head.rstrip() + "…"
