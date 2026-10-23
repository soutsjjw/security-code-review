#!/usr/bin/env python3
"""檢查 Skill 指令與拆分的標準文件是否完整、可按需定位。"""
from __future__ import annotations

import re
from pathlib import Path
from review_queue import STANDARD_GUIDES

STANDARD_CATALOGS = {
    "tacert_v2_checks": "standards/tacert-v2-checklist.yaml",
    "owasp_2025_categories": "standards/owasp-top10-2025.yaml",
    "system_baseline_v13_controls": "standards/tw-system-baseline-v1.3.yaml",
    "web_guide_v32_checks": "standards/nics-web-guide-v3.2.yaml",
    "web_guide_v32_appendix1": "standards/nics-web-v3.2-appendix1.yaml",
    "web_guide_v32_appendix3": "standards/nics-web-v3.2-appendix3.yaml",
}
OLD_SECTION_HEADINGS = (
    "## TACERT「網站安全管理指南」V2 補充檢核",
    "## OWASP Top 10:2025 十類風險對照",
    "## 《資通系統防護基準驗證實務》V1.3 第二層驗證",
    "## WEB 應用程式安全參考指引 V3.2（限定 ASP.NET/.NET 與通用 Web 安全）",
    "## 附件 1：Web 應用程式安全查檢表（V3.2 主文件附錄）",
    "## 附件 3：HTTP 安全標頭防護設定（六項 CR-05 技術子檢核）",
)
DOC_LINK = re.compile(r"\]\((docs/[^)#]+\.md)(?:#[^)]+)?\)")


def documentation_errors(root: Path) -> list[str]:
    """檢查 SKILL.md 的標準文件對照、實體存在性及相對路徑。"""
    errors: list[str] = []
    main_path = root / "SKILL.md"
    if not main_path.is_file():
        return ["缺少 SKILL.md"]
    main = main_path.read_text(encoding="utf-8")
    if "## 共同證據與結果判定（所有規範均適用）" not in main:
        errors.append("SKILL.md 缺少共用證據／判定硬性規則")
    if "## 標準文件按需載入（必須執行）" not in main or "--detail-id" not in main:
        errors.append("SKILL.md 缺少按規則讀取標準文件的指令")
    if any(heading in main for heading in OLD_SECTION_HEADINGS):
        errors.append("SKILL.md 仍包含應移至 docs 的長篇標準章節")

    links = set(DOC_LINK.findall(main))
    if set(STANDARD_GUIDES) != set(STANDARD_CATALOGS):
        errors.append("標準文件欄位映射與必備 YAML 清冊不一致")
    if len(set(STANDARD_GUIDES.values())) != len(STANDARD_GUIDES):
        errors.append("多個標準欄位指向同一份 Markdown，需分開保留專屬限制")

    for field, doc in STANDARD_GUIDES.items():
        if f"`{field}`" not in main or doc not in links:
            errors.append(f"{field}: SKILL.md 未完整引用標準文件 {doc}")
        candidate = root / doc
        if not candidate.is_file():
            errors.append(f"缺少按需載入文件：{doc}")
            continue
        body = candidate.read_text(encoding="utf-8")
        catalog = STANDARD_CATALOGS.get(field)
        if catalog and (catalog not in body or not (root / catalog).is_file()):
            errors.append(f"{doc}: 標準清冊引用不存在或不一致：{catalog}")
        if "[SKILL.md](../SKILL.md)" not in body:
            errors.append(f"{doc}: 未引用共用證據／狀態判定規則")
        if len(body.strip()) < 300:
            errors.append(f"{doc}: 標準專屬查核說明過短，可能遺漏內容")
    for relative in links:
        if not (root / relative).is_file():
            errors.append(f"SKILL.md Markdown 連結不存在：{relative}")
    return errors


if __name__ == "__main__":
    import sys
    root = Path(__file__).resolve().parents[1]
    errors = documentation_errors(root)
    for error in errors:
        print("ERROR:", error, file=sys.stderr)
    if errors:
        sys.exit(1)
    print("PASS: Skill standard documentation verified")
