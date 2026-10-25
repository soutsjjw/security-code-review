#!/usr/bin/env python3
"""受控第一輪補正：驗證來源引用、分類及明確補正理由，不生成安全結論。"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from partial_review import _snapshot
from review_scope import ScopeError
from source_reader import read_source_text


def verify_amendments(root: Path, category: str, amendments: Any,
                      allowed_ids: set[str]) -> dict[str, set[str]]:
    """回傳規則對應已核實的來源路徑，拒絕沒有可定位原始碼證據的補正。"""
    if not isinstance(amendments, dict) or not amendments:
        raise ScopeError("第一輪補正必須提供 first_pass_amendments 規則證據")
    snapshot = _snapshot(root)
    allowed_paths = snapshot["source_hashes"]
    reviewed: dict[str, set[str]] = {}
    for rid, entry in amendments.items():
        if rid not in allowed_ids or not rid.startswith(category + "-"):
            raise ScopeError(f"第一輪補正包含未選分類規則：{rid}")
        if not isinstance(entry, dict) or set(entry) != {"reason", "source_evidence"}:
            raise ScopeError(f"{rid}: 補正理由與 source_evidence 欄位不完整")
        reason, evidence = entry["reason"], entry["source_evidence"]
        if not isinstance(reason, str) or len(reason.strip()) < 20:
            raise ScopeError(f"{rid}: 必須記錄具體補正理由（至少 20 字）")
        if not isinstance(evidence, list) or not evidence:
            raise ScopeError(f"{rid}: 補正須引用真實來源檔、行號、雜湊及片段")
        paths: set[str] = set()
        for row in evidence:
            if not isinstance(row, dict) or set(row) != {
                    "path", "sha256", "line_start", "line_end", "excerpt"}:
                raise ScopeError(f"{rid}: source_evidence 格式無效")
            path, sha = row["path"], row["sha256"]
            start, end, excerpt = row["line_start"], row["line_end"], row["excerpt"]
            if not isinstance(path, str) or path not in allowed_paths:
                raise ScopeError(f"{rid}: 來源路徑不在當次固定快照：{path}")
            if not isinstance(sha, str) or sha != allowed_paths[path]:
                raise ScopeError(f"{rid}: 來源 SHA256 與快照不一致：{path}")
            if type(start) is not int or type(end) is not int or start < 1 or end < start:
                raise ScopeError(f"{rid}: 來源行號不合法：{path}")
            if not isinstance(excerpt, str) or len(excerpt.strip()) < 8:
                raise ScopeError(f"{rid}: 須提供具體來源片段：{path}")
            raw = (root / path).read_bytes()
            if hashlib.sha256(raw).hexdigest() != sha:
                raise ScopeError(f"{rid}: 核對來源時檔案已異動：{path}")
            lines = read_source_text(root / path)[0].splitlines()
            if end > len(lines) or excerpt.strip() not in "\n".join(lines[start - 1:end]):
                raise ScopeError(f"{rid}: 來源片段與行號無法對應：{path}")
            paths.add(path)
        reviewed[rid] = paths
    return reviewed
