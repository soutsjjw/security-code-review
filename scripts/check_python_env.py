#!/usr/bin/env python3
"""只讀檢查 Python 版本及 requirements.txt；不安裝套件或建立審查檔。"""
from __future__ import annotations

import argparse
import importlib
from importlib import metadata
from itertools import zip_longest
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
MODULE_NAMES = {"pyyaml": "yaml", "jsonschema": "jsonschema", "referencing": "referencing"}
REQUIREMENT = re.compile(r"^([A-Za-z0-9_.-]+)\s*(.*)$")
CONSTRAINT = re.compile(r"^(>=|<=|==|!=|>|<)\s*(\d+(?:\.\d+)*)$")
VERSION = re.compile(r"^(\d+(?:\.\d+)*)(.*)$")


def release_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split("."))


def cmp_release(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    for left, right in zip_longest(a, b, fillvalue=0):
        if left != right:
            return 1 if left > right else -1
    return 0


def satisfies(actual: str, specifier: str) -> bool:
    match = VERSION.match(actual)
    if not match:
        return False
    got = release_tuple(match.group(1))
    suffix = match.group(2).lower()
    prerelease = bool(re.match(r"(?:a|b|rc|dev)\d*", suffix))
    for item in specifier.split(","):
        constraint = CONSTRAINT.fullmatch(item.strip())
        if not constraint:
            raise ValueError(f"不支援的相依版本條件：{item}")
        operator, required = constraint.groups()
        diff = cmp_release(got, release_tuple(required))
        if prerelease and diff == 0:
            diff = -1
        if not {
            ">=": diff >= 0, ">": diff > 0, "<": diff < 0,
            "<=": diff <= 0, "==": diff == 0, "!=": diff != 0,
        }[operator]:
            return False
    return True


def check_environment(requirements: Path = ROOT / "requirements.txt") -> list[str]:
    errors = []
    if sys.version_info < (3, 10):
        errors.append("需要 Python 3.10 以上版本")
    for raw in requirements.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        matched = REQUIREMENT.fullmatch(line)
        if not matched:
            errors.append(f"無法解析 requirements.txt：{line}")
            continue
        package, specifier = matched.groups()
        module = MODULE_NAMES.get(package.lower().replace("-", "_"))
        if not module:
            errors.append(f"尚未支援的必要套件：{package}")
            continue
        try:
            installed = metadata.version(package)
            importlib.import_module(module)
        except (metadata.PackageNotFoundError, ImportError):
            errors.append(f"缺少必要套件：{package}{specifier}")
            continue
        if specifier and not satisfies(installed, specifier):
            errors.append(f"套件版本不符：{package} {installed}（需要 {specifier}）")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="唯讀檢查 Python 及 Skill 相依套件")
    parser.add_argument("--quiet", action="store_true", help="僅回傳狀態碼")
    args = parser.parse_args()
    try:
        errors = check_environment()
    except (OSError, ValueError) as exc:
        errors = [str(exc)]
    if not args.quiet:
        if errors:
            for msg in errors:
                print(f"ERROR: {msg}", file=sys.stderr)
        else:
            print(f"PASS: Python {sys.version.split()[0]} ({sys.executable}) 與 requirements.txt 相依套件均可用")
    return 2 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
