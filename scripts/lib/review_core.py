#!/usr/bin/env python3
"""無相依的共用底層：canonical JSON 摘要、SHA256、JSON 讀寫與來源快照指紋。

本模組不得匯入任何其他審查模組，供各層向下依賴以避免循環匯入。
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

# 受測專案內的審查工件根目錄（相對 TARGET_ROOT）；各模組由此推得自己的檔案路徑。
REPORT_ROOT = Path("reports/security-code-review")
ANALYSIS_ROOT = REPORT_ROOT / "analysis"


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha256(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_digest(value: Any) -> str:
    """排序鍵、緊湊分隔、保留非 ASCII 的 JSON SHA256；既有證據摘要皆依此格式。"""
    return sha256_bytes(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                   separators=(",", ":")).encode("utf-8"))


def json_bytes(value: Any, *, sort_keys: bool = False) -> bytes:
    """報告與證據 JSON 的唯一序列化格式：UTF-8、縮排 2、固定 LF 與結尾換行，跨平台位元組一致。"""
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=sort_keys) + "\n").encode("utf-8")


def write_json_atomic(path: Path, value: Any, *, sort_keys: bool = False) -> None:
    """同目錄唯一暫存檔寫入並 fsync 後 os.replace；失敗時清除暫存，不留下截斷 JSON。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(json_bytes(value, sort_keys=sort_keys))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def write_json_exclusive(path: Path, value: Any, *, sort_keys: bool = False) -> None:
    """僅在檔案不存在時建立並 fsync；既有檔案代表未完成交易或不可覆寫的紀錄，一律拒絕。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(json_bytes(value, sort_keys=sort_keys))
        handle.flush()
        os.fsync(handle.fileno())


def read_json(path: Path, default: Any = None) -> Any:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else default


def snapshot_fingerprint(snapshot: dict[str, Any]) -> str:
    """將完整 Git 版本與所有來源 SHA256 固定成單一指紋，避免漏檔新增時沿用舊 pass。"""
    return canonical_digest({"git_revision": snapshot.get("git_revision"),
                             "source_hashes": snapshot.get("source_hashes")})
