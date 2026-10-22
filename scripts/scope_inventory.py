#!/usr/bin/env python3
"""記錄來源盤點與實際審查範圍；盤點到的檔案不視為已完成審查。"""
from __future__ import annotations

import os
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

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


def _in_project(path: str, project_path: str) -> bool:
    return project_path == "." or path.startswith(project_path.rstrip("/") + "/")


def build_scope_inventory(
    assessment: dict[str, Any], source_root: Path, *,
    ignored_artifacts: Iterable[Path | None] = (),
) -> dict[str, Any]:
    """只從受測工作目錄計算，不採信人工輸入的專案／檔案數量。"""
    root = source_root.resolve()
    if not root.is_dir():
        raise ValueError(f"受測根目錄不存在：{source_root}")
    # 產生與驗證時皆略過同一批報告輸出；避免輸出報告反過來改變原始碼盤點。
    ignored = {
        resolved.relative_to(root).as_posix()
        for resolved in (Path(p).resolve() for p in ignored_artifacts if p is not None)
        if resolved.is_relative_to(root)
    }
    details = assessment.get("scope_details") or {}
    custom_excludes = []
    seen = set()
    for item in details.get("excluded_paths", []):
        path = relative_path(root, item["path"], root_allowed=True)
        if path == ".":
            raise ValueError("不可排除整個受測根目錄")
        if path in seen:
            raise ValueError(f"重複的排除路徑：{path}")
        seen.add(path)
        custom_excludes.append((path, item["reason"]))

    excluded: dict[tuple[str, str], int] = defaultdict(int)
    eligible: set[str] = set()
    inventoried = 0
    for current, directories, filenames in os.walk(root, followlinks=False):
        directories[:] = [d for d in directories if not (Path(current) / d).is_symlink()]
        for name in filenames:
            absolute = Path(current) / name
            if not absolute.is_file() or absolute.is_symlink():
                continue
            rel = absolute.relative_to(root).as_posix()
            if rel in ignored:
                continue
            inventoried += 1
            rule = next(((p, reason) for p, reason in custom_excludes
                         if rel == p or rel.startswith(p.rstrip("/") + "/")), None)
            if rule is None:
                rule = _default_rule(rel)
            if rule:
                excluded[rule] += 1
            else:
                eligible.add(rel)

    # 只有 verified file_reviews 可出現在正式「實際審查檔案清單」；
    # 即使 inspected_paths 把數百個檔案掛在一個規則，也不得灌水。
    from source_coverage import build_source_coverage
    coverage = build_source_coverage(assessment, root, ignored_artifacts=ignored_artifacts)
    if coverage["review_integrity_errors"]:
        raise ValueError("逐檔檢核紀錄驗證失敗：" + coverage["review_integrity_errors"][0])
    inspected: dict[str, set[str]] = defaultdict(set)
    for path, rule_ids in coverage["reviewed_file_rule_ids"].items():
        if path not in eligible:
            raise ValueError(f"驗證來源不在盤點範圍：{path}")
        inspected[path].update(rule_ids)

    reviewed_files = [{"path": p, "check_ids": sorted(ids)} for p, ids in sorted(inspected.items())]
    project_rows = []
    declared = details.get("projects", [])
    project_paths = set()
    for item in declared:
        path = relative_path(root, item["path"], root_allowed=True, directory=True)
        if path in project_paths:
            raise ValueError(f"重複的專案路徑：{path}")
        project_paths.add(path)
        project_rows.append({"name": item["name"], "path": path,
                             "reviewed_file_count": sum(_in_project(p, path) for p in inspected)})
    exclusion_rows = [{"path": p, "reason": reason, "file_count": count}
                      for (p, reason), count in sorted(excluded.items())]
    for p, reason in custom_excludes:
        if (p, reason) not in excluded:
            exclusion_rows.append({"path": p, "reason": reason, "file_count": 0})
    exclusion_rows.sort(key=lambda x: x["path"])
    return {
        "basis": "working-tree-filesystem",
        "inventory_file_count": inventoried,
        "eligible_file_count": len(eligible),
        "excluded_file_count": inventoried - len(eligible),
        "reviewed_file_count": len(reviewed_files),
        "reviewed_files": reviewed_files,
        "file_types": sorted({Path(p).suffix.lower() or "（無副檔名）" for p in inspected}),
        "declared_project_count": len(project_rows) if declared else None,
        "reviewed_project_count": sum(p["reviewed_file_count"] > 0 for p in project_rows) if declared else None,
        "projects": project_rows,
        "excluded_paths": exclusion_rows,
    }
