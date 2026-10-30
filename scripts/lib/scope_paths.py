#!/usr/bin/env python3
"""受測目錄的相對路徑驗證與預設排除目錄；不匯入任何上層審查模組。"""
from __future__ import annotations

import re
from pathlib import Path

# 不排除 .github 等 CI 設定。
EXCLUDED_DIRS = {
    ".git": "Git 內部資料",
    "node_modules": "第三方相依套件",
    "vendor": "第三方相依套件",
    "bin": "建置輸出",
    "obj": "建置輸出",
    "dist": "建置輸出",
    "build": "建置輸出",
    "target": "建置輸出",
    ".venv": "虛擬環境",
    "venv": "虛擬環境",
    ".pytest_cache": "測試快取",
    "__pycache__": "測試快取",
    "reports": "產出報告",
    ".codegraph": "CodeGraph 索引",
}


def relative_path(root: Path, raw: str, *, root_allowed: bool = False, directory: bool = False) -> str:
    """檢查相對路徑、存在性與 symlink 越界，回傳 POSIX 路徑。"""
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(f"無效的審查範圍路徑：{raw!r}")
    value = raw.replace("\\", "/")
    if value.startswith("/") or re.match(r"^[A-Za-z]:", value) or "\x00" in value:
        raise ValueError(f"審查範圍不得使用絕對路徑：{raw!r}")
    parts = [part for part in value.split("/") if part not in ("", ".")]
    if ".." in parts:
        raise ValueError(f"審查範圍路徑不可跨出受測目錄：{raw!r}")
    if not parts and not root_allowed:
        raise ValueError(f"審查範圍路徑不可為空：{raw!r}")
    clean = "/".join(parts) if parts else "."
    actual = (root / clean).resolve()
    if not actual.is_relative_to(root):
        raise ValueError(f"審查範圍路徑跨出受測目錄：{raw!r}")
    if directory and not actual.is_dir():
        raise ValueError(f"專案目錄不存在：{raw!r}")
    if not directory and not root_allowed and not actual.is_file():
        raise ValueError(f"審查檔案不存在：{raw!r}")
    return clean


def _default_rule(path: str) -> tuple[str, str] | None:
    parts = path.split("/")
    for i, part in enumerate(parts[:-1]):
        if part.startswith(".codegraph-"):
            return "**/.codegraph-*/", "CodeGraph 平台索引"
        if part in EXCLUDED_DIRS:
            return "**/" + part + "/", EXCLUDED_DIRS[part]
        if i + 1 < len(parts) - 1 and part in (".agents", ".claude") and parts[i + 1] == "skills":
            return "**/" + part + "/skills/", "Agent Skill 套件"
    return None
