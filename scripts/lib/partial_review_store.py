#!/usr/bin/env python3
"""分類審查工件的路徑、來源快照與讀取驗證；供分類流程、守門與報告共用。

本模組不得匯入 partial_review／partial_review_safety／partial_report。
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any

from review_scope import CATEGORY_COUNTS, PARTIAL_ROOT, ScopeError
from source_coverage import build_source_coverage
from review_core import canonical_digest as _digest

STAGED_FILE = Path("analysis/staged/pending.json")
SNAPSHOT_FILE = Path("analysis/source-snapshot.json")
BASELINE = Path("analysis/first-pass-baseline.json")
CLOSURES = Path("analysis/rule-closures.json")
VERIFICATIONS = Path("analysis/control-verifications.json")
AUDITS = Path("analysis/decision-audits.json")
REVIEWS = Path("analysis/adversarial-reviews.json")
HISTORY = Path("analysis/second-pass-history")
EVIDENCE_FILES = {"closures": CLOSURES, "control_verifications": VERIFICATIONS,
                  "decision_audits": AUDITS, "adversarial_reviews": REVIEWS}


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _git_revision(root: Path) -> str:
    result = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else "not-a-git-repository"


def _snapshot(root: Path) -> dict[str, Any]:
    # 使用正式來源盤點的相同排除範圍，不把 reports/ 或 Skill 當成受測檔案。
    coverage = build_source_coverage({"checks": [], "file_reviews": []}, root)
    files = {path: hashlib.sha256((root / path).read_bytes()).hexdigest()
             for path in coverage["source_paths"]}
    revision = _git_revision(root)
    return {"git_revision": revision, "source_hashes": files,
            "fingerprint": _digest({"git_revision": revision, "source_hashes": files})}


def _category_dir(root: Path, category: str) -> Path:
    if category not in CATEGORY_COUNTS:
        raise ScopeError(f"未支援分類：{category}")
    root = root.resolve()
    directory = root / PARTIAL_ROOT / category
    # 禁止 reports/、partial/ 或分類目錄的 symlink 導向受測專案外部。
    current = directory
    while current != root:
        if current.is_symlink():
            raise ScopeError(f"分類輸出路徑不允許 symbolic link：{current}")
        current = current.parent
    if not directory.resolve().is_relative_to(root):
        raise ScopeError("分類輸出路徑超出受測專案")
    return directory


def _artifact(root: Path, category: str, relative: Path | str) -> Path:
    """只可寫入分類私有目錄；拒絕任何中間 symlink。"""
    directory = _category_dir(root, category)
    path = directory / relative
    if path == directory or not path.resolve().is_relative_to(directory.resolve()):
        raise ScopeError("分類工件路徑無效")
    current = path
    while current != directory:
        if current.is_symlink():
            raise ScopeError(f"分類工件路徑不允許 symbolic link：{current}")
        current = current.parent
    return path


def _category_rules(catalog: dict, category: str) -> list[dict]:
    return [rule for rule in catalog["rules"] if rule["category"] == category]


def _assert_assessment(data: Any, category: str, catalog: dict) -> None:
    expected = [r["id"] for r in _category_rules(catalog, category)]
    if not isinstance(data, dict) or data.get("review_mode") != "partial" or data.get("category") != category:
        raise ScopeError(f"{category}: assessment 的分類身分無效")
    checks = data.get("checks")
    if (not isinstance(checks, list) or len(checks) != len(expected)
            or [c.get("id") for c in checks if isinstance(c, dict)] != expected):
        raise ScopeError(f"{category}: checks 必須按規則主檔順序精確涵蓋 {len(expected)} 項")
    if data.get("ruleset_version") != catalog["ruleset_version"]:
        raise ScopeError(f"{category}: 規則版本不符")
    if (not isinstance(data.get("findings"), list)
            or not isinstance(data.get("file_reviews"), list)):
        raise ScopeError(f"{category}: findings/file_reviews 格式錯誤")
    if data.get("source_snapshot_sha256") is None:
        raise ScopeError(f"{category}: 缺少來源快照識別")


def _verify_snapshot(root: Path, directory: Path, assessment: dict) -> None:
    stored_path = _artifact(root, assessment["category"], SNAPSHOT_FILE)
    if not stored_path.is_file():
        raise ScopeError("缺少分類來源快照；不可沿用舊有 completed")
    stored = _load(stored_path)
    if (not isinstance(stored, dict) or stored.get("fingerprint") != _digest({
            "git_revision": stored.get("git_revision"),
            "source_hashes": stored.get("source_hashes"),
        })):
        raise ScopeError("分類來源快照內容損壞")
    if assessment["source_snapshot_sha256"] != stored["fingerprint"]:
        raise ScopeError("assessment 與來源快照識別不一致")
    if _snapshot(root) != stored:
        raise ScopeError("來源檔案或 Git Revision 已異動；拒絕沿用分類審查證據")


def read_category(root: Path, category: str, catalog: dict) -> dict:
    directory = _category_dir(root, category)
    path = directory / "assessment.json"
    if not path.is_file():
        raise ScopeError(f"{category}: 尚無分類進度，請先指定 --init")
    assessment = _load(path)
    _assert_assessment(assessment, category, catalog)
    _verify_snapshot(root, directory, assessment)
    return assessment
