#!/usr/bin/env python3
"""記錄來源盤點與實際審查範圍；盤點到的檔案不視為已完成審查。"""
from __future__ import annotations

import json
import os
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

import source_coverage
from scope_paths import _default_rule, relative_path


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
    coverage = source_coverage.build_source_coverage(assessment, root, ignored_artifacts=ignored_artifacts)
    if coverage["review_integrity_errors"]:
        raise ValueError("逐檔檢核紀錄驗證失敗：" + coverage["review_integrity_errors"][0])
    inspected: dict[str, set[str]] = defaultdict(set)
    for path, rule_ids in coverage["reviewed_file_rule_ids"].items():
        if path not in eligible:
            raise ValueError(f"驗證來源不在盤點範圍：{path}")
        inspected[path].update(rule_ids)

    reviewed_files = [{"path": p, "check_ids": sorted(ids)} for p, ids in sorted(inspected.items())]
    source_paths = set(coverage["source_paths"])
    unreviewed_eligible = [
        {
            "path": p,
            "reason": ("屬應審查來源檔，但缺少有效逐檔紀錄"
                       if p in source_paths else
                       "非強制逐檔的原始碼／設定檔類型；已盤點但未計入來源覆蓋率"),
        }
        for p in sorted(eligible - set(inspected))
    ]
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
        "source_file_count": coverage["source_file_count"],
        "reviewed_source_file_count": coverage["reviewed_source_file_count"],
        "missing_source_file_count": coverage["missing_source_file_count"],
        "eligible_unreviewed_file_count": len(unreviewed_eligible),
        "eligible_unreviewed_files": unreviewed_eligible,
        "reviewed_files": reviewed_files,
        "file_types": sorted({Path(p).suffix.lower() or "（無副檔名）" for p in inspected}),
        "declared_project_count": len(project_rows) if declared else None,
        "reviewed_project_count": sum(p["reviewed_file_count"] > 0 for p in project_rows) if declared else None,
        "projects": project_rows,
        "excluded_paths": exclusion_rows,
    }


def detect_projects(source_root: Path) -> list[dict[str, str]]:
    """唯讀掃描 .csproj，回傳可直接寫入 scope_details.projects 的清單。

    只是盤點線索；Agent 仍須確認各專案是否納入本次審查，不可僅憑此推定專案數。
    """
    root = source_root.resolve()
    rows: list[dict[str, str]] = []
    for current, directories, filenames in os.walk(root, followlinks=False):
        rel_dir = Path(current).relative_to(root).as_posix()
        directories[:] = sorted(
            d for d in directories
            if not (Path(current) / d).is_symlink()
            and _default_rule((Path(rel_dir) / d / "x").as_posix().lstrip("./")) is None)
        for name in sorted(filenames):
            if name.lower().endswith(".csproj"):
                rows.append({"name": Path(name).stem, "path": rel_dir if rel_dir != "." else "."})
    return sorted(rows, key=lambda r: (r["path"], r["name"]))


def scope_project_issues(assessment: dict[str, Any], source_root: Path) -> tuple[list[str], list[str]]:
    """(errors, warnings)：有 .csproj 卻沒有宣告 scope_details.projects 時拒絕；漏宣告的專案警示。"""
    detected = detect_projects(source_root)
    if not detected:
        return [], []
    declared = (assessment.get("scope_details") or {}).get("projects") or []
    sample = json.dumps(detected[:3], ensure_ascii=False)
    if not declared:
        return [f"scope_details.projects 未宣告，但盤點到 {len(detected)} 個 .csproj；"
                "請寫入實際納入的專案（可執行 scope_inventory.py --target <TARGET_ROOT> 取得清單），"
                f"例如 {sample}"], []
    declared_paths = {str(p.get("path", "")).replace("\\", "/").strip("/") or "." for p in declared if isinstance(p, dict)}
    missing = [d for d in detected if d["path"] not in declared_paths]
    if missing:
        names = "、".join(f"{d['name']}（{d['path']}）" for d in missing[:8])
        return [], [f"盤點到 {len(missing)} 個 .csproj 未列入 scope_details.projects：{names}；"
                    "若確定不在本次範圍，請在 excluded_paths 說明"]
    return [], []


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="列出受測目錄的 .csproj，供填寫 scope_details.projects")
    parser.add_argument("--target", type=Path, required=True)
    args = parser.parse_args()
    # JSON CLI 固定輸出 UTF-8；Windows 重新導向 stdout 時的系統預設可能是 cp950。
    import sys
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    print(json.dumps(detect_projects(args.target), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
