#!/usr/bin/env python3
"""唯讀調查逐檔 SHA256 差異；不自動重算 assessment，不把差異歸咎於 BOM／CRLF。"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from scope_paths import relative_path
from source_reader import digest_matches, source_digest
from review_core import REPORT_ROOT

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def audit_hashes(assessment: dict[str, Any], source_root: Path) -> dict[str, Any]:
    root = source_root.resolve()
    details: list[dict[str, Any]] = []
    stats = {"total": 0, "raw_match": 0, "compatible_match": 0,
             "content_mismatch": 0, "invalid_digest": 0, "unreadable": 0}
    for index, row in enumerate(assessment.get("file_reviews", [])):
        stats["total"] += 1
        raw_path = row.get("path") if isinstance(row, dict) else None
        stored = row.get("sha256") if isinstance(row, dict) else None
        item: dict[str, Any] = {"index": index, "path": raw_path, "stored_sha256": stored}
        if not isinstance(stored, str) or not _SHA256.fullmatch(stored):
            item.update(status="invalid_digest", reason="審查紀錄中的 SHA256 不符合 64 位小寫十六進位")
            stats["invalid_digest"] += 1
        else:
            try:
                path = relative_path(root, raw_path)
                contents = (root / path).read_bytes()
            except (ValueError, TypeError, OSError) as exc:
                item.update(status="unreadable", reason=str(exc))
                stats["unreadable"] += 1
            else:
                raw_digest = hashlib.sha256(contents).hexdigest()
                canonical_digest = source_digest(contents)
                if stored == raw_digest:
                    item["status"] = "raw_match"
                    stats["raw_match"] += 1
                elif digest_matches(stored, contents):
                    item.update(status="compatible_match",
                                reason="雜湊可由既有 BOM／CRLF 相容規則解釋")
                    stats["compatible_match"] += 1
                else:
                    item.update(status="content_mismatch",
                                reason="原始雜湊及既有 BOM／CRLF 變體均不符；須核對版本與來源內容",
                                current_raw_sha256=raw_digest,
                                current_canonical_sha256=canonical_digest)
                    stats["content_mismatch"] += 1
        # 僅列出需處置與非原始位元組相符的紀錄；不輸出程式碼內容。
        if item["status"] != "raw_match":
            details.append(item)
    return {
        "source_root": str(root),
        "summary": stats,
        "issues": sorted(details, key=lambda x: (str(x["path"]), x["index"])),
        "note": ("compatible_match 不需要自動改寫審查紀錄；content_mismatch 不能僅依雜湊"
                 "判定改動性質，必須比較審查版本及現行來源，必要時重做逐檔審查。"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="唯讀列出全部逐檔 SHA256 差異與原因")
    parser.add_argument("--target", required=True, type=Path, help="被審查專案根目錄")
    parser.add_argument("--assessment", type=Path, help="預設 <target>/reports/security-code-review/assessment.json")
    args = parser.parse_args()
    root = args.target.resolve()
    path = args.assessment or root / REPORT_ROOT / "assessment.json"
    try:
        assessment = json.loads(path.read_text(encoding="utf-8"))
        result = audit_hashes(assessment, root)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print("ERROR:", exc, file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 1 if any(result["summary"][key] for key in
                    ("content_mismatch", "invalid_digest", "unreadable")) else 0


if __name__ == "__main__":
    raise SystemExit(main())
