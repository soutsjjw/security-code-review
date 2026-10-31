#!/usr/bin/env python3
"""DP-01／DP-04 的「掃描證實相依弱點」證據：lockfile 實際來源行 + 已保存的掃描輸出。

只能支持 fail：清單內的套件版本行本身不是掃描機制，不能證明已持續掃描或已更新；
它只有在同一檢核附上 SHA256 吻合、內文含真實命令輸出且列出同一套件與版本的
掃描工件時，才可作為「該版本確有已知弱點」的定位證據。pass 仍須真實掃描機制。
"""
from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Any

from review_core import REPORT_ROOT, sha256_bytes
from source_reader import read_source_text

SCAN_PROVEN_RULES = frozenset({"DP-01", "DP-04"})
# 僅接受套件清單／lockfile；集中版本開關（ManagePackageVersionsCentrally）不含套件與版本，
# 不會解析出任何套件，仍然無法作為證據。
DEPENDENCY_MANIFEST_NAMES = frozenset({
    "packages.lock.json", "Directory.Packages.props", "libman.json", "package-lock.json",
})
DEPENDENCY_MANIFEST_SUFFIXES = frozenset({".csproj"})
ARTIFACT_ROOT = REPORT_ROOT / "artifacts"
ARTIFACT_SUFFIXES = (".txt", ".json")
ARTIFACT_ID = re.compile(r"^scan:([a-z0-9]+(?:-[a-z0-9]+)*)$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
# 片段過長會讓整份 lockfile 搭便車；一個套件節點加上其相依清單通常在此範圍內。
MAX_EXCERPT_LINES = 30
# 真實命令輸出特徵；只有敘述文字（「已掃描，有弱點」）不算。
SCAN_OUTPUT_SIGNATURES = re.compile(
    r"has the following vulnerable packages"
    r"|has the following updates to its packages"
    r"|\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b"
    r"|\bCVE-\d{4}-\d{4,}\b"
    r"|^\s*(?:>\s*)?Top-level Package\s+Requested\s+Resolved\s+Latest\b"
    r"|^\s*(?:>\s*)?Transitive Package\s+Resolved\s+Latest\b",
    re.IGNORECASE | re.MULTILINE,
)
_VERSION = r"\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.\-]+)?"
_LOCK_NAME = re.compile(r'^\s*"(?:node_modules/)?((?:@[\w.\-]+/)?[\w.\-]+)"\s*:\s*\{\s*$')
_LOCK_VERSION = re.compile(r'^\s*"(?:resolved|version)"\s*:\s*"(' + _VERSION + r')"\s*,?\s*$')
_MSBUILD_ITEM = re.compile(r"<Package(?:Reference|Version)\b[^>]*>", re.IGNORECASE)
_MSBUILD_NAME = re.compile(r'\b(?:Include|Update)\s*=\s*"([\w.\-]+)"', re.IGNORECASE)
_MSBUILD_VERSION = re.compile(r'\bVersion\s*=\s*"(' + _VERSION + r')"', re.IGNORECASE)
_LIBMAN = re.compile(r'"library"\s*:\s*"((?:@[\w.\-]+/)?[\w.\-]+)@(' + _VERSION + r')"')


def is_dependency_manifest(path: str) -> bool:
    name = PurePosixPath(path).name
    return name in DEPENDENCY_MANIFEST_NAMES or PurePosixPath(name).suffix.lower() in DEPENDENCY_MANIFEST_SUFFIXES


def excerpt_packages(path: str, lines: list[str]) -> set[tuple[str, str]]:
    """從片段解析「套件名稱 + 解析版本」；版本為變數或範圍時不算。"""
    if not is_dependency_manifest(path):
        return set()
    name = PurePosixPath(path).name
    pairs: set[tuple[str, str]] = set()
    if name in {"packages.lock.json", "package-lock.json"}:
        current: str | None = None
        for line in lines:
            named = _LOCK_NAME.match(line)
            if named:
                current = named.group(1)
                continue
            version = _LOCK_VERSION.match(line)
            if version and current:
                pairs.add((current, version.group(1)))
                current = None
    elif name == "libman.json":
        pairs.update(_LIBMAN.findall("\n".join(lines)))
    else:
        for item in _MSBUILD_ITEM.findall(" ".join(lines)):
            named, version = _MSBUILD_NAME.search(item), _MSBUILD_VERSION.search(item)
            if named and version:
                pairs.add((named.group(1), version.group(1)))
    return pairs


def artifact_file(target: Path, artifact_id: Any) -> tuple[Path | None, str | None]:
    """artifact_id `scan:<slug>` 對應 `artifacts/scan-<slug>.txt|.json`；拒絕越界與 symlink。"""
    match = ARTIFACT_ID.fullmatch(artifact_id) if isinstance(artifact_id, str) else None
    if not match:
        return None, f"artifact_id {artifact_id!r} 須為 scan:<小寫英數與連字號>"
    folder = (target / ARTIFACT_ROOT).resolve()
    if not folder.is_relative_to(target.resolve()) or any(
            p.is_symlink() for p in (target / ARTIFACT_ROOT, target / REPORT_ROOT)):
        return None, "掃描工件目錄越界或包含 symbolic link"
    found = [target / ARTIFACT_ROOT / f"scan-{match.group(1)}{suffix}" for suffix in ARTIFACT_SUFFIXES]
    found = [p for p in found if p.is_file() or p.is_symlink()]
    if len(found) != 1:
        return None, (f"{artifact_id}: 找不到 {ARTIFACT_ROOT.as_posix()}/scan-{match.group(1)}.txt"
                      if not found else f"{artifact_id}: 同名 .txt 與 .json 工件並存，無法唯一對應")
    if found[0].is_symlink():
        return None, f"{artifact_id}: 掃描工件不可為 symbolic link"
    return found[0], None


def verified_scan_artifacts(target: Path, evidence: Any) -> tuple[list[str], list[tuple[str, str]]]:
    """回傳 (錯誤, [(artifact_id, 內文)])：只收 SHA256 吻合且含實際命令輸出特徵的工件。

    其他命名的 scan 證據（例如 CI 紀錄）不納入此路徑；以 `scan:` 命名者任一筆不合格即整體拒絕。
    """
    errors: list[str] = []
    verified: list[tuple[str, str]] = []
    scans = [e for e in evidence or [] if isinstance(e, dict) and e.get("kind") == "scan"
             and isinstance(e.get("artifact_id"), str) and e["artifact_id"].startswith("scan:")]
    if not scans:
        return ["缺少 kind=scan 且 artifact_id 為 scan:<名稱> 的掃描工件證據"], verified
    for ev in scans:
        artifact_id = ev.get("artifact_id")
        file, issue = artifact_file(target, artifact_id)
        if issue:
            errors.append(issue)
            continue
        recorded = ev.get("sha256")
        if not isinstance(recorded, str) or not SHA256.fullmatch(recorded):
            errors.append(f"{artifact_id}: scan 證據須記錄工件的 sha256")
            continue
        raw = file.read_bytes()
        if sha256_bytes(raw) != recorded:
            errors.append(f"{artifact_id}: 掃描工件 SHA256 與證據紀錄不符，工件已變更或不是同一份輸出")
            continue
        try:
            text = read_source_text(file, raw=raw)[0]
        except (UnicodeError, ValueError) as exc:
            errors.append(f"{artifact_id}: 無法解碼掃描工件：{exc}")
            continue
        if not SCAN_OUTPUT_SIGNATURES.search(text):
            errors.append(f"{artifact_id}: 工件沒有實際掃描命令輸出特徵（弱點清單標頭、GHSA／CVE 或 Resolved／Latest 欄位）")
            continue
        verified.append((artifact_id, text))
    return errors, verified


def _listed(text: str, package: str, version: str) -> bool:
    """套件名稱與版本須出現在掃描輸出的同一行。"""
    name = re.compile(r"(?<![\w.\-/@])" + re.escape(package) + r"(?![\w.\-])", re.IGNORECASE)
    ver = re.compile(r"(?<![\w.\-])" + re.escape(version) + r"(?![\w.\-])")
    return any(name.search(line) and ver.search(line) for line in text.splitlines())


def scan_proven_errors(target: Path, rule_id: str, status: Any, path: str,
                       lines: list[str], evidence: Any) -> list[str]:
    """空清單代表此片段可作為 DP-01／DP-04 fail 的掃描證實定位證據。"""
    if rule_id not in SCAN_PROVEN_RULES:
        return [f"{rule_id}: 掃描證實相依弱點路徑只適用 DP-01／DP-04"]
    if status != "fail":
        return [f"{rule_id}: 套件清單行只能支持 fail；pass／review 須有真實掃描機制或工件"]
    if not is_dependency_manifest(path):
        return [f"{rule_id}: {path} 不是允許的套件清單或 lockfile"]
    if len(lines) > MAX_EXCERPT_LINES:
        return [f"{rule_id}: {path} 片段超過 {MAX_EXCERPT_LINES} 行，須精確定位弱點套件節點"]
    pairs = excerpt_packages(path, lines)
    if not pairs:
        return [f"{rule_id}: {path} 片段未含可解析的套件名稱與解析版本（集中版本開關不算）"]
    errors, artifacts = verified_scan_artifacts(target, evidence)
    if errors or not artifacts:
        return [f"{rule_id}: {issue}" for issue in errors]
    if not any(_listed(text, package, version) for package, version in pairs for _, text in artifacts):
        listed = "、".join(f"{p} {v}" for p, v in sorted(pairs))
        return [f"{rule_id}: 掃描工件內文找不到片段的套件與版本（{listed}）"]
    return []
