#!/usr/bin/env python3
"""技術分析器註冊與工具探測；探測結果不是安全審查證據。"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

MODERN_TFMS = re.compile(r"^(?:netcoreapp[1-9]\d*(?:\.\d+)?|net(?:[5-9]|[1-9]\d)\.\d+)(?:[-+].*)?$", re.I)
LEGACY_TFMS = re.compile(r"^net(?:[1-4]\d{1,2}|framework)", re.I)


class AnalysisAdapter(Protocol):
    name: str
    def detect(self, root: Path) -> dict: ...


def _tfms(project: Path) -> list[str]:
    tree = ET.parse(project)
    root = tree.getroot()
    found: list[str] = []
    for element in root.iter():
        name = element.tag.rsplit("}", 1)[-1]
        if name in ("TargetFramework", "TargetFrameworks") and element.text:
            found.extend(t.strip() for t in element.text.split(";") if t.strip())
        if name == "TargetFrameworkVersion" and element.text:
            found.append(element.text.strip())
    if not found:
        props = project.parent / "Directory.Build.props"
        if props.is_file():
            found = _tfms(props)
    return sorted(set(found))


@dataclass(frozen=True)
class ModernDotNetAdapter:
    name: str = "dotnet-modern"

    def detect(self, root: Path) -> dict:
        projects: list[dict] = []
        ignored = {".git", "bin", "obj", "node_modules", "reports", ".codegraph", ".agents", ".claude"}
        for current, directories, files in os.walk(root, followlinks=False):
            directories[:] = [d for d in directories
                              if d not in ignored and not (Path(current) / d).is_symlink()]
            for filename in files:
                if not filename.lower().endswith(".csproj"):
                    continue
                p = Path(current) / filename
                try:
                    tfms = _tfms(p)
                except (OSError, ET.ParseError) as exc:
                    tfms = []
                    error = str(exc)
                else:
                    error = ""
                is_modern = bool(tfms) and all(MODERN_TFMS.match(t) for t in tfms)
                projects.append({"path": p.relative_to(root).as_posix(), "target_frameworks": tfms,
                                 "supported": is_modern, "reason": error or ("" if is_modern else "未知、非現代 .NET 或混合傳統 TFM")})
        return {"adapter": self.name, "projects": sorted(projects, key=lambda p: p["path"]),
                "supported": bool(projects) and all(p["supported"] for p in projects)}


# 介面及註冊位置保留給未來的 .NET Framework、Vue，以及混合專案分析器。
ADAPTERS: tuple[AnalysisAdapter, ...] = (ModernDotNetAdapter(),)


def probe_codegraph(root: Path) -> dict:
    executable = shutil.which("codegraph")
    if not executable:
        return {"available": False, "reason": "未找到 codegraph CLI；沿用來源讀取與關聯追蹤"}
    # 不會自行 codegraph init（該命令會在受測專案建立索引）。
    if not (root / ".codegraph").is_dir():
        return {"available": False, "reason": "受測根目錄尚未建立 .codegraph 索引"}
    try:
        status = subprocess.run([executable, "status", str(root)], capture_output=True,
                                text=True, timeout=12, check=False, cwd=root)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"available": False, "reason": f"CodeGraph 狀態檢查失敗：{type(exc).__name__}"}
    if status.returncode != 0:
        return {"available": False, "reason": "CodeGraph 索引無法使用；改用原始碼工具"}
    return {"available": True, "command": "codegraph explore <query>",
            "mcp_tool": "codegraph_explore",
            "note": "僅用於來源定位與呼叫鏈；需核對實際證據及索引新鮮度"}


def probe_roslyn() -> dict:
    executable = shutil.which("dotnet")
    if not executable:
        return {"available": False, "reason": "未找到 dotnet SDK；Roslyn 分析降級"}
    try:
        version = subprocess.run([executable, "--version"], capture_output=True,
                                 text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return {"available": False, "reason": "dotnet SDK 無法啟動"}
    if version.returncode or not version.stdout.strip():
        return {"available": False, "reason": "無法讀取 dotnet SDK 版本"}
    try:
        major = int(version.stdout.strip().split(".")[0])
    except ValueError:
        return {"available": False, "reason": "dotnet SDK 版本無法解析"}
    if major < 8:
        return {"available": False, "reason": "Roslyn 工具需要 .NET SDK 8 以上"}
    return {"available": True, "executable": executable, "sdk_version": version.stdout.strip(),
            "target_framework": f"net{major}.0"}
