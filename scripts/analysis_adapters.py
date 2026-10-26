#!/usr/bin/env python3
"""技術分析器註冊與工具探測；探測結果不是安全審查證據。"""
from __future__ import annotations

import json
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


def _framework_values(values: list[str]) -> list[str]:
    """只接受已解析的 TFM 字串；不猜測尚未展開的 MSBuild 變數。"""
    result: set[str] = set()
    for value in values:
        for part in value.split(";"):
            token = part.strip()
            if not token:
                continue
            if "$(" in token or "%(" in token or "@(" in token:
                raise ValueError("TargetFramework 仍包含未展開的 MSBuild 表達式")
            result.add(token)
    return sorted(result)


def _requires_msbuild(project: Path, tree: ET.ElementTree, literal: list[str]) -> bool:
    """判定能否安全採用純字面值；匯入/條件屬性必須由 MSBuild 真正評估。"""
    if not literal:
        return True
    for node in tree.iter():
        local = node.tag.rsplit("}", 1)[-1]
        if local in {"Import", "ImportGroup", "Choose", "When", "Otherwise"}:
            return True
        if any(key.rsplit("}", 1)[-1] == "Condition" for key in node.attrib):
            return True
        if local in {"TargetFramework", "TargetFrameworks", "TargetFrameworkVersion"}:
            if node.text and any(expr in node.text for expr in ("$(", "@(", "%(")):
                return True
    # MSBuild 會從專案目錄一路向上找最近的 Directory.Build.props，
    # 並可在 Directory.Build.targets 後期覆寫屬性；不採用錯誤的同目錄解析捷徑。
    for directory in (project.parent, *project.parent.parents):
        if (directory / "Directory.Build.props").is_file():
            return True
        if (directory / "Directory.Build.targets").is_file():
            return True
    return False


def _evaluated_tfms(project: Path) -> list[str]:
    """使用 MSBuild 17.8+ 僅評估匯入後的屬性，不呼叫 Build/Restore/Target。"""
    executable = shutil.which("dotnet")
    if not executable:
        raise ValueError("專案採用匯入／條件式 TFM，但找不到 dotnet SDK 可執行 MSBuild 屬性評估")
    command = [
        executable, "msbuild", str(project), "-nologo", "-verbosity:quiet",
        "-getProperty:TargetFramework,TargetFrameworks,TargetFrameworkVersion",
    ]
    env = dict(os.environ, DOTNET_CLI_TELEMETRY_OPTOUT="1", DOTNET_NOLOGO="1",
               DOTNET_SKIP_FIRST_TIME_EXPERIENCE="1",
               DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE="1",
               MSBUILDDISABLENODEREUSE="1")
    try:
        result = subprocess.run(
            command, cwd=project.parent, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=30, check=False, env=env
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"MSBuild 唯讀 TFM 評估無法執行（{type(exc).__name__}）") from exc
    if result.returncode != 0:
        raise ValueError(f"MSBuild TFM 評估失敗（exit {result.returncode}，可能缺少相容 SDK／匯入）")
    try:
        document = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError("MSBuild 未輸出可解析的屬性 JSON（需要 MSBuild 17.8+）") from exc
    props = document.get("Properties") if isinstance(document, dict) else None
    if not isinstance(props, dict):
        raise ValueError("MSBuild 回應缺少 Properties")
    values = []
    for property_name in ("TargetFramework", "TargetFrameworks"):
        value = props.get(property_name, "")
        if not isinstance(value, str):
            raise ValueError(f"MSBuild {property_name} 格式不正確")
        if value.strip():
            values.append(value)
    if not values:
        value = props.get("TargetFrameworkVersion", "")
        if not isinstance(value, str):
            raise ValueError("MSBuild TargetFrameworkVersion 格式不正確")
        if value.strip():
            values.append(value)
    return _framework_values(values)


def _tfms(project: Path) -> list[str]:
    tree = ET.parse(project)
    literal: list[str] = []
    for element in tree.getroot().iter():
        name = element.tag.rsplit("}", 1)[-1]
        if name in ("TargetFramework", "TargetFrameworks", "TargetFrameworkVersion") and element.text:
            literal.append(element.text)
    if _requires_msbuild(project, tree, literal):
        return _evaluated_tfms(project)
    return _framework_values(literal)


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
                if p.is_symlink():
                    continue
                try:
                    tfms = _tfms(p)
                except (OSError, ET.ParseError, ValueError) as exc:
                    tfms = []
                    error = str(exc)
                else:
                    error = ""
                is_modern = bool(tfms) and all(MODERN_TFMS.fullmatch(t) for t in tfms)
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
