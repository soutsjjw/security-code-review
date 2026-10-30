#!/usr/bin/env python3
"""assessment 內部一致性檢查：Finding 與檢核狀態連動、判定理由矛盾、佔位字、review 比例。

這是保守的機械檢查，不判斷安全結論是否正確；只攔截資料自相矛盾的情況。
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from source_reader import read_source_text
from analysis_adapters import ModernDotNetAdapter

# 「保留 review」「故為 review」等語句出現在 pass／fail 的判定理由中，代表狀態與理由不一致。
STATUS_CONTRADICTION = re.compile(r"(保留|維持|仍為|故為|列為|沿用|仍屬)\s*[`'\"「]?\s*review", re.IGNORECASE)
PLACEHOLDER_VALUES = ("待實際盤點", "未能自動辨識")
REVIEW_KIND_STATIC = "static_done_external_pending"
REVIEW_KIND_EXTERNAL = "external_only"
REVIEW_KIND_DELEGATED = "external_responsibility_pending"
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
        "delegated": sum(c.get("review_kind") == REVIEW_KIND_DELEGATED for c in review),
        "unclassified": sum(c.get("review_kind") not in (REVIEW_KIND_STATIC, REVIEW_KIND_EXTERNAL, REVIEW_KIND_DELEGATED) for c in review),
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
    """重用與結構索引相同的 MSBuild 屬性評估；失敗保留佔位，不猜測框架。"""

    detection = ModernDotNetAdapter().detect(target)
    if not detection["supported"]:
        return PLACEHOLDER_VALUES[1] + "（Agent 須依實際盤點填寫）"
    frameworks = {tfm for project in detection["projects"]
                  for tfm in project["target_frameworks"]}
    is_web = False
    for project in detection["projects"]:
        path = target / project["path"]
        try:
            content = path.read_text(encoding="utf-8-sig", errors="replace")
        except OSError:
            continue
        is_web = is_web or 'Sdk="Microsoft.NET.Sdk.Web"' in content
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


# ---- Finding 品質啟發式（需要來源）-------------------------------------------------
# 局部變數宣告：var／內建型別／PascalCase 型別 name = ...
_DECLARATION = re.compile(
    r"\b(?:var|string|int|long|bool|double|decimal|object|byte\[\]|[A-Z]\w*(?:<[^>\n]+>)?)\s+([A-Za-z_]\w*)\s*=(?!=)")
_COMMENT_LINE = re.compile(r"(//|/\*|\*\s|@\*|<!--|#\s)")
_DESIGN_NOTE = re.compile(
    r"不加入|不使用|不支援|選配|刻意|暫時|已知|因為|原因|無法|by design|intentional|optional|not supported|workaround|TODO",
    re.IGNORECASE)
_LINE_REF = re.compile(r"第\s*(\d+)\s*(?:[-～~至到]\s*(\d+))?\s*行|[Ll]ines?\s*(\d+)(?:\s*[-–]\s*(\d+))?|:(\d+)\b")
IMPACT_TYPES = ("confidentiality", "integrity", "availability")
_IMPACT_LABEL = {"confidentiality": "機密性", "integrity": "完整性", "availability": "可用性"}


def impact_type_label(finding: dict[str, Any]) -> str:
    types = [t for t in finding.get("impact_type", []) if t in _IMPACT_LABEL]
    return "、".join(_IMPACT_LABEL[t] for t in types)


def _finding_text(finding: dict[str, Any]) -> str:
    parts = [str(finding.get("title", "")), str(finding.get("impact", ""))]
    parts += [str(e.get("description", "")) for e in finding.get("evidence", []) if isinstance(e, dict)]
    return "\n".join(parts)


def _narrow_line_refs(text: str) -> set[int]:
    """文字中明確點名的單行或 3 行內的小範圍；寬範圍（如 55-78）不視為逐行指涉。"""
    lines: set[int] = set()
    for m in _LINE_REF.finditer(text):
        a, b = (m.group(1), m.group(2)) if m.group(1) else (
            (m.group(3), m.group(4)) if m.group(3) else (m.group(5), None))
        start = int(a)
        end = int(b) if b else start
        if end - start <= 2:
            lines.update(range(start, end + 1))
    return lines


def finding_quality_issues(data: dict[str, Any], source_root: Path) -> tuple[list[str], list[str]]:
    """回傳 (errors, warnings)。啟發式：僅攔截明顯問題，不能取代人工複核。

    - 死碼：Finding 點名（以名稱或單行行號）的局部變數在整個檔案只宣告一次、從未使用，
      不得當作風險路徑；已追查確實有使用者，須在 verification.usage_traced 說明。
    - 設計說明註解：引用片段前後 3 行有說明刻意設計或已知限制的註解時警示；
      須在 verification.design_notes 記錄已納入判斷。
    - impact_type：高嚴重度卻只有可用性影響時警示；未標示者彙總提示。
    """
    errors: list[str] = []
    warnings: list[str] = []
    missing_type = 0
    for finding in data.get("findings", []):
        if not isinstance(finding, dict):
            continue
        fid = finding.get("id", "?")
        verification = finding.get("verification") or {}
        traced = bool(str(verification.get("usage_traced", "")).strip())
        noted = bool(str(verification.get("design_notes", "")).strip())
        text = _finding_text(finding)
        cited_lines = _narrow_line_refs(text)
        dead_seen: set[tuple[str, str]] = set()
        note_seen = False
        for ev in finding.get("evidence", []):
            if not (isinstance(ev, dict) and ev.get("kind") == "source" and ev.get("path")
                    and isinstance(ev.get("line_start"), int) and isinstance(ev.get("line_end"), int)):
                continue
            try:
                source = read_source_text(source_root / ev["path"])[0]
            except (OSError, UnicodeError, ValueError):
                continue
            lines = source.splitlines()
            start, end = ev["line_start"], min(ev["line_end"], len(lines))
            if not traced:
                for no in range(start, end + 1):
                    for m in _DECLARATION.finditer(lines[no - 1]):
                        name = m.group(1)
                        if name == "_" or (ev["path"], name) in dead_seen:
                            continue
                        if len(re.findall(rf"(?<![\w.]){re.escape(name)}(?!\w)", source)) != 1:
                            continue
                        if re.search(rf"(?<!\w){re.escape(name)}(?!\w)", text) or no in cited_lines:
                            dead_seen.add((ev["path"], name))
                            errors.append(
                                f"{fid}: {ev['path']}:{no} 的變數 {name} 只宣告、從未使用（疑似死碼），"
                                "不得當作風險路徑；若已追查確實有使用，請在 verification.usage_traced 說明")
            if not noted and not note_seen:
                lo, hi = max(1, start - 3), min(len(lines), end + 3)
                for no in range(lo, hi + 1):
                    line = lines[no - 1]
                    if _COMMENT_LINE.search(line) and _DESIGN_NOTE.search(line):
                        warnings.append(
                            f"{fid}: {ev['path']}:{no} 附近有設計說明註解（{line.strip()[:50]}）；"
                            "請確認判斷已納入，並於 verification.design_notes 記錄")
                        note_seen = True
                        break
        types = finding.get("impact_type")
        if not types:
            missing_type += 1
        elif finding.get("severity") in ("critical", "high") and set(types) == {"availability"}:
            warnings.append(f"{fid}: 嚴重度 {finding.get('severity')} 但 impact_type 只有可用性；"
                            "請確認是否真的達到該等級，或補上機密性／完整性影響")
    if missing_type:
        warnings.append(f"{missing_type} 筆 Finding 未標示 impact_type（confidentiality／integrity／availability）")
    return errors, warnings
