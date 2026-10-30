#!/usr/bin/env python3
"""產生或校驗 Skill 套件的 SHA256SUMS.txt；只讀檔案，不修改其他套件內容。

涵蓋範圍為 Git 追蹤檔（非 Git 安裝則為實際檔案），排除隱藏檔、Python 快取與清單本身。
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from review_core import file_sha256 as _sha256

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = "SHA256SUMS.txt"


def _included(rel: str) -> bool:
    parts = rel.split("/")
    return (rel != MANIFEST and not rel.endswith(".pyc")
            and not any(p.startswith(".") or p == "__pycache__" for p in parts))


def package_files(root: Path = ROOT) -> list[str]:
    """Git 工作目錄以追蹤檔為準，避免把本機暫存檔寫入清單。"""
    try:
        top = subprocess.run(["git", "-C", str(root), "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True, check=True).stdout.strip()
        if Path(top).resolve() == root.resolve():
            out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"],
                                 capture_output=True, check=True).stdout
            return sorted(r for r in out.decode("utf-8").split("\0")
                          if r and _included(r) and (root / r).is_file())
    except (OSError, subprocess.CalledProcessError):
        pass
    return sorted(r for r in (p.relative_to(root).as_posix()
                              for p in root.rglob("*") if p.is_file()) if _included(r))


def render(root: Path = ROOT) -> str:
    return "".join(f"{_sha256(root / rel)}  {rel}\n" for rel in package_files(root))


def manifest_errors(root: Path = ROOT) -> list[str]:
    path = root / MANIFEST
    if not path.is_file():
        return [f"{MANIFEST} missing"]
    recorded: dict[str, str] = {}
    errors: list[str] = []
    for number, line in enumerate(path.read_text("utf-8").splitlines(), 1):
        digest, sep, rel = line.partition("  ")
        if not sep or len(digest) != 64 or not rel:
            errors.append(f"{MANIFEST}:{number} malformed line")
            continue
        recorded[rel] = digest
    expected = set(package_files(root))
    errors += [f"{MANIFEST} missing entry: {rel}" for rel in sorted(expected - set(recorded))]
    errors += [f"{MANIFEST} lists absent or excluded file: {rel}" for rel in sorted(set(recorded) - expected)]
    for rel in sorted(expected & set(recorded)):
        if _sha256(root / rel) != recorded[rel]:
            errors.append(f"{MANIFEST} hash mismatch: {rel}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="重新產生 SHA256SUMS.txt")
    mode.add_argument("--check", action="store_true", help="校驗清單與目前檔案是否一致")
    args = parser.parse_args(argv)
    if args.write:
        (ROOT / MANIFEST).write_bytes(render().encode("utf-8"))
        print(f"wrote {MANIFEST}: {len(package_files())} files")
        return 0
    errors = manifest_errors()
    for error in errors:
        print("ERROR:", error, file=sys.stderr)
    if errors:
        print("修正方式：確認變更無誤後執行 scripts/package_manifest.py --write", file=sys.stderr)
        return 1
    print(f"PASS: {MANIFEST} verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
