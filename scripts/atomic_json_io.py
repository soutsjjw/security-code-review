#!/usr/bin/env python3
"""同目錄原子 JSON 寫入；有限重試 Windows 短暫分享／存取衝突。

僅保護單一檔案的落盤，並非多檔案交易，也不放寬證據雜湊驗證。
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import time
from typing import Any

# Windows WinError 5 = ACCESS_DENIED、32 = SHARING_VIOLATION。
# 只重試這兩種系統回傳，不吞掉永久拒絕／一般 I/O 失敗。
WINDOWS_RETRY_ERRORS = frozenset((5, 32))
REPLACE_DELAYS = (0.025, 0.05, 0.1, 0.2, 0.4)


def _replace(source: Path, dest: Path) -> None:
    os.replace(source, dest)


def atomic_write_json(path: Path, value: Any) -> None:
    """每次建立獨立暫存，flush+fsync 後單檔 replace，成功或失敗皆清理暫存。

    Windows 防毒掃描或檔案分享鎖可能短暫阻擋 replace；有限次重試後
    照原樣拋出錯誤，原目的檔維持不被截斷。
    """
    path = Path(path)
    payload = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp",
                                        dir=path.parent)
    temp = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        for delay in (*REPLACE_DELAYS, None):
            try:
                _replace(temp, path)
                return
            except OSError as exc:
                if delay is None or getattr(exc, "winerror", None) not in WINDOWS_RETRY_ERRORS:
                    raise
                time.sleep(delay)
    finally:
        temp.unlink(missing_ok=True)
