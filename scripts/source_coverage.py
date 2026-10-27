#!/usr/bin/env python3
"""比對應審查的原始碼／設定檔與確實記錄的逐檔審查，防止 70/70 假性完工。"""
from __future__ import annotations

import os
import hashlib
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from scope_inventory import _default_rule, relative_path
from file_review_integrity import CATEGORIES, verified_file_rule_reviews

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


def expected_paths(root: Path, excluded_paths: list[str],
                   ignored: set[str] | None = None) -> set[str]:
    """單次輕量目錄盤點；此清單不是已完成審查或有效證據。"""
    ignored = ignored or set()
    expected: set[str] = set()
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = [
            name for name in directories
            if not (Path(current) / name).is_symlink()
            and not _default_rule((Path(current) / name / "entry").relative_to(root).as_posix())
            and not any(
                (Path(current) / name).relative_to(root).as_posix() == path
                or (Path(current) / name).relative_to(root).as_posix().startswith(path.rstrip("/") + "/")
                for path in excluded_paths
            )
        ]
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
    return expected


def provisional_source_coverage(assessment: dict[str, Any], source_root: Path) -> dict[str, Any]:
    """僅供 --compact 顯示下一批待查來源，不讀內容、不驗證 SHA 或安全結論。

    預覽統計不得作為交付依據；正式 build_source_coverage 必須重新逐檔核對。
    """
    root = source_root.resolve()
    if not root.is_dir():
        raise ValueError("受測來源目錄不存在")
    excluded = []
    for item in (assessment.get("scope_details") or {}).get("excluded_paths", []):
        path = relative_path(root, item["path"], root_allowed=True)
        if path == ".":
            raise ValueError("不可排除全部受測目錄")
        excluded.append(path)
    expected = expected_paths(root, excluded)
    completed = {
        row["id"]: set((row.get("execution") or {}).get("inspected_paths") or [])
        for row in assessment.get("checks", [])
        if (row.get("execution") or {}).get("state") == "completed"
    }
    # 不檢查來源內容，僅把具備基本形狀的紀錄列為「候選已審查」。
    candidates: set[str] = set()
    for row in assessment.get("file_reviews") or []:
        if not isinstance(row, dict):
            continue
        path = row.get("path")
        if path not in expected or not isinstance(row.get("sha256"), str):
            continue
        screening = row.get("category_screening")
        reviews = row.get("rule_reviews")
        if not isinstance(screening, dict) or set(screening) != set(CATEGORIES):
            continue
        if not isinstance(reviews, list):
            continue
        if all(isinstance(rr, dict) and isinstance(rr.get("rule_id"), str)
               and path in completed.get(rr["rule_id"], set()) for rr in reviews):
            candidates.add(path)
    missing = sorted(expected - candidates)
    counts = Counter(Path(path).suffix.lower() or Path(path).name for path in missing)
    return {
        "source_file_count": len(expected),
        "reviewed_source_file_count": len(candidates),
        "missing_source_file_count": len(missing),
        "missing_source_paths": missing,
        "missing_by_type": dict(sorted(counts.items())),
        "review_integrity_errors": [],
        "verified": False,
    }



def unverified_inspected_paths(
    assessment: dict[str, Any], expected: set[str], verified: dict[str, set[str]],
) -> dict[str, Any]:
    """Group rule/file links rejected by the authoritative file verifier.

    These are diagnostics only: an existing row does not prove that its SHA,
    rule applicability, line numbers, or control evidence is valid.
    """
    reviews: dict[str, dict[str, Any]] = {}
    for row in assessment.get("file_reviews") or []:
        if isinstance(row, dict) and isinstance(row.get("path"), str):
            reviews.setdefault(row["path"], row)
    by_rule: Counter[str] = Counter()
    by_reason: Counter[str] = Counter()
    by_path: Counter[str] = Counter()
    reason_by_path: dict[str, Counter[str]] = {}
    examples: list[dict[str, str]] = []
    link_lines: list[str] = []
    for check in assessment.get("checks") or []:
        if not isinstance(check, dict) or not isinstance(check.get("id"), str):
            continue
        if (check.get("execution") or {}).get("state") != "completed":
            continue
        rid = check["id"]
        recorded = (check.get("execution") or {}).get("inspected_paths") or []
        if not isinstance(recorded, list):
            continue
        for path in sorted(set(p for p in recorded if isinstance(p, str)) & expected):
            if rid in verified.get(path, set()):
                continue
            row = reviews.get(path)
            if row is None:
                reason = "missing_file_review"
            elif not isinstance(row.get("rule_reviews"), list) or not any(
                    isinstance(item, dict) and item.get("rule_id") == rid
                    for item in row["rule_reviews"]):
                reason = "missing_rule_review"
            else:
                reason = "invalid_file_review"
            by_rule[rid] += 1
            by_reason[reason] += 1
            by_path[path] += 1
            reason_by_path.setdefault(path, Counter())[reason] += 1
            link_lines.append(f"{rid}\t{path}\t{reason}")
            if len(examples) < 10:
                examples.append({"rule_id": rid, "path": path, "reason": reason})
    return {
        "total": sum(by_rule.values()),
        "fingerprint": hashlib.sha256("\n".join(sorted(link_lines)).encode("utf-8")).hexdigest(),
        "by_rule": dict(sorted(by_rule.items())),
        "by_reason": dict(sorted(by_reason.items())),
        "affected_file_count": len(by_path),
        "top_paths": [
            {"path": path, "invalid_links": count,
             "by_reason": dict(sorted(reason_by_path[path].items()))}
            for path, count in sorted(by_path.items(), key=lambda item: (-item[1], item[0]))[:30]
        ],
        "examples": examples,
        "verified": False,
        "note": "僅分類已被正式驗證器拒絕的規則／檔案關聯；不能據此直接更改檢核結論",
    }


def build_source_coverage(assessment: dict[str, Any], source_root: Path, *,
                          ignored_artifacts: Iterable[Path | None] = (),
                          selected_categories: tuple[str, ...] = CATEGORIES) -> dict[str, Any]:
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
    expected = expected_paths(root, excluded_paths, ignored)

    # 只計入已驗證逐檔 10 類規則篩選、SHA256 和行號佐證的來源。
    verified, integrity_errors = verified_file_rule_reviews(
        assessment, root, expected, selected_categories=selected_categories)
    inspected = set(verified)
    link_gaps = unverified_inspected_paths(assessment, expected, verified)

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
        "unverified_inspected_paths": link_gaps,
        "reviewed_file_rule_ids": {p: sorted(ids) for p, ids in sorted(verified.items())},
    }
