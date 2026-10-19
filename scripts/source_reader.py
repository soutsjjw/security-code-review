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
