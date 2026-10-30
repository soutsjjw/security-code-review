#!/usr/bin/env python3
"""無相依的共用底層：canonical JSON 摘要、SHA256、JSON 讀取與來源快照指紋。

本模組不得匯入任何其他審查模組，供各層向下依賴以避免循環匯入。
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha256(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_digest(value: Any) -> str:
    """排序鍵、緊湊分隔、保留非 ASCII 的 JSON SHA256；既有證據摘要皆依此格式。"""
    return sha256_bytes(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                   separators=(",", ":")).encode("utf-8"))


def read_json(path: Path, default: Any = None) -> Any:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else default


def snapshot_fingerprint(snapshot: dict[str, Any]) -> str:
    """將完整 Git 版本與所有來源 SHA256 固定成單一指紋，避免漏檔新增時沿用舊 pass。"""
    return canonical_digest({"git_revision": snapshot.get("git_revision"),
                             "source_hashes": snapshot.get("source_hashes")})
