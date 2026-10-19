#!/usr/bin/env python3
"""唯讀、嚴格解碼來源檔，供來源行號與 Before Code 核對共用。"""
from __future__ import annotations

import codecs
from pathlib import Path

DEFAULT_LEGACY_ENCODINGS = ("cp950", "cp1252")


def read_source_text(path: Path, legacy_encodings: tuple[str, ...] = DEFAULT_LEGACY_ENCODINGS) -> tuple[str, str]:
    raw = path.read_bytes()
    if raw.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        candidates = ("utf-32",)
    elif raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        candidates = ("utf-16",)
    elif raw.startswith(codecs.BOM_UTF8):
        candidates = ("utf-8-sig",)
    else:
        candidates = ("utf-8", *legacy_encodings)
    errors = []
    for encoding in dict.fromkeys(candidates):
        try:
            decoded = raw.decode(encoding, errors="strict")
            if "\x00" in decoded:
                raise UnicodeError("含 NUL，可能是二進位檔或無 BOM 的 UTF-16")
            return decoded, encoding
        except (UnicodeError, LookupError) as exc:
            errors.append(f"{encoding}: {exc}")
    raise UnicodeError(f"{path}: 無法安全解碼（{'；'.join(errors)}）")


def main() -> int:
    """供 Codex 呼叫的唯讀來源擷取工具，輸出帶真實行號的內容。"""
    import argparse
    import sys

    # Windows 重導向管線可能是 CP950；包含 argparse 錯誤訊息也統一輸出 UTF-8。
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(description="安全解碼來源檔，不需互動確認也不會修改原檔")
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--path", required=True, help="相對於 source-root 的檔案路徑")
    parser.add_argument("--start", type=int, default=1)
    parser.add_argument("--end", type=int, default=200)
    parser.add_argument("--source-encodings", default=",".join(DEFAULT_LEGACY_ENCODINGS))
    args = parser.parse_args()
    root = args.source_root.resolve()
    candidate = args.path.replace("\\", "/")
    if candidate.startswith(("/", "//")) or len(candidate) > 1 and candidate[1] == ":":
        parser.error("來源路徑必須是相對路徑")
    if args.start < 1 or args.end < args.start or args.end - args.start + 1 > 1000:
        parser.error("行號必須有效，且單次最多讀取 1000 行")
    path = (root / candidate).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        parser.error("路徑不得超出受測專案，且檔案必須存在")
    encodings = tuple(x.strip() for x in args.source_encodings.split(",") if x.strip())
    try:
        source, encoding = read_source_text(path, encodings)
    except (OSError, UnicodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if encoding in encodings:
        print(f"WARN: {candidate}: 使用候選舊式編碼 {encoding} 唯讀解碼，請在審查限制記錄", file=sys.stderr)
    for line_no, line in enumerate(source.splitlines(), 1):
        if args.start <= line_no <= args.end:
            print(f"{line_no}: {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
