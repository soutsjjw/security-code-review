#!/usr/bin/env python3
"""比對應審查的原始碼／設定檔與確實記錄的逐檔審查，防止 70/70 假性完工。"""
from __future__ import annotations

import os
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from scope_inventory import _default_rule, relative_path
from file_review_integrity import verified_file_rule_reviews

# 只納入可閱讀的程式碼、程式設定及專案檔；不把圖片／DLL／文件當原始碼。
# 尤其 .cs 必須全數涵蓋，不能只以抽樣或規則總數代替。
SOURCE_SUFFIXES = frozenset({
    ".cs", ".csx", ".cshtml", ".razor", ".vb", ".vbs", ".fs", ".fsx",
    ".aspx", ".ascx", ".ashx", ".asmx", ".master",
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
    ".py", ".go", ".rs", ".rb", ".php", ".java", ".kt", ".swift",
    ".c", ".cc", ".cpp", ".h", ".hpp", ".sql", ".sh", ".ps1", ".bat", ".cmd",
    ".html", ".htm", ".xml", ".config", ".json", ".jsonc",
    ".yaml", ".yml", ".toml", ".ini", ".env", ".tf", ".tfvars",
    ".csproj", ".vbproj", ".fsproj", ".sln", ".slnx", ".props", ".targets",
})
SOURCE_FILENAMES = frozenset({
    "Dockerfile", "Containerfile", "Jenkinsfile", "Makefile", "CMakeLists.txt",
    ".gitignore", ".dockerignore", "NuGet.Config", "Directory.Build.props",
    "Directory.Build.targets", "Directory.Packages.props", "global.json",
    "Gemfile", "Rakefile", "Procfile",
})


def build_source_coverage(assessment: dict[str, Any], source_root: Path, *, ignored_artifacts: Iterable[Path | None] = ()) -> dict[str, Any]:
    """以實際工作目錄計算應審查檔案，僅 completed 的真實路徑算已審查。

    此函式驗證紀錄的覆蓋性，但不能代替 Agent 真正閱讀程式碼。
    """
    root = source_root.resolve()
    if not root.is_dir():
        raise ValueError(f"受測目錄不存在：{source_root}")
    details = assessment.get("scope_details") or {}
    excluded_paths = []
    for item in details.get("excluded_paths", []):
        path = relative_path(root, item["path"], root_allowed=True)
        if path == ".":
            raise ValueError("不可排除整個受測根目錄")
        excluded_paths.append(path)

    ignored = {
        resolved.relative_to(root).as_posix()
        for resolved in (Path(p).resolve() for p in ignored_artifacts if p is not None)
        if resolved.is_relative_to(root)
    }
    expected: set[str] = set()
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = [name for name in directories
                          if not (Path(current) / name).is_symlink()]
        for name in files:
            absolute = Path(current) / name
            if not absolute.is_file() or absolute.is_symlink():
                continue
            rel = absolute.relative_to(root).as_posix()
            if rel in ignored or _default_rule(rel) or any(
                rel == path or rel.startswith(path.rstrip("/") + "/")
                for path in excluded_paths
            ):
                continue
            if absolute.suffix.lower() in SOURCE_SUFFIXES or name in SOURCE_FILENAMES:
                expected.add(rel)

    # 只計入已驗證逐檔 10 類規則篩選、SHA256 和行號佐證的來源。
    verified, integrity_errors = verified_file_rule_reviews(assessment, root, expected)
    inspected = set(verified)

    missing = sorted(expected - inspected)
    counts = Counter(Path(path).suffix.lower() or Path(path).name for path in missing)
    return {
        "source_file_count": len(expected),
        "source_paths": sorted(expected),
        "reviewed_source_file_count": len(expected & inspected),
        "missing_source_file_count": len(missing),
        "missing_source_paths": missing,
        "missing_by_type": dict(sorted(counts.items())),
        "review_integrity_errors": integrity_errors,
        "reviewed_file_rule_ids": {p: sorted(ids) for p, ids in sorted(verified.items())},
    }
