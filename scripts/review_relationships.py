#!/usr/bin/env python3
"""保守的 .NET 跨檔關聯候選；這些邊不是已驗證的呼叫鏈或安全結論。"""
from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from source_reader import read_source_text

_TYPES = re.compile(r"\b(?:class|interface|record|struct)\s+([A-Za-z_]\w*)")
_DI = re.compile(r"\bAdd(?:Scoped|Transient|Singleton)\s*<\s*([\w.]+)\s*,\s*([\w.]+)\s*>")
_DI_FACTORY = re.compile(r"\bAdd(?:Scoped|Transient|Singleton)\s*<\s*([\w.]+)\s*>")
_OPTIONS = re.compile(r"\b(?:GetSection|GetRequiredSection)\s*\(\s*\"([^\"]+)\"")
_CONFIG = re.compile(r"\b(?:Configuration|configuration|config)\s*\[\s*\"([^\"]+)\"\s*\]")
_AUTH = re.compile(r"\[(?:Authorize|AllowAnonymous)(?:Attribute)?(?:\s*\(|\s*\])|\.(?:RequireAuthorization|AllowAnonymous)\s*\(")
_MIDDLEWARE = re.compile(r"\b(?:UseRouting|UseAuthentication|UseAuthorization|UseCors|UseSession|UseHttpsRedirection|UseHsts|UseExceptionHandler|MapControllers|MapRazorPages|MapGroup)\s*\(")


def _edge(kind: str, source: str, line: int, *, target: str | None = None,
          symbol: str = "", detail: str = "", callsite_id: str = "") -> dict:
    basis = f"{kind}|{source}|{line}|{target or ''}|{symbol}|{detail}"
    if callsite_id:
        basis += "|" + callsite_id
    edge = {
        "id": hashlib.sha256(basis.encode("utf-8")).hexdigest()[:20],
        "kind": kind, "source": source, "line": line,
        "target": target, "symbol": symbol, "detail": detail,
        "resolution": "candidate_only",
    }
    if callsite_id:
        edge["callsite_id"] = callsite_id
    return edge


def build_relationships(root: Path, source_paths: list[str],
                        call_hints: dict[str, list[dict]] | None = None) -> list[dict]:
    """建立具類型的跨檔與組態線索；所有路徑均來自已盤點的來源清單。"""
    paths = set(source_paths)
    cs = [p for p in source_paths if p.lower().endswith(".cs")]
    source_lines: dict[str, list[str]] = {}
    symbols: dict[str, set[str]] = {}
    for path in cs:
        try:
            lines = read_source_text(root / path)[0].splitlines()
        except (OSError, UnicodeError, ValueError):
            continue
        source_lines[path] = lines
        for line in lines:
            for m in _TYPES.finditer(line):
                symbols.setdefault(m.group(1), set()).add(path)

    config_files = [p for p in source_paths if Path(p).name.startswith("appsettings")
                    and Path(p).suffix.lower() in {".json", ".jsonc"}]
    startup_files = [p for p in cs if Path(p).name in {"Program.cs", "Startup.cs"}]
    result: dict[str, dict] = {}

    def add(edge: dict) -> None:
        result[edge["id"]] = edge

    for path, lines in source_lines.items():
        for number, line in enumerate(lines, 1):
            for match in _DI.finditer(line):
                service, implementation = (x.split(".")[-1] for x in match.groups())
                for target in sorted(symbols.get(implementation, ())):
                    if target != path:
                        add(_edge("di_registration", path, number, target=target,
                                  symbol=service, detail=implementation))
            for match in _DI_FACTORY.finditer(line):
                symbol = match.group(1).split(".")[-1]
                if not _DI.search(line):
                    add(_edge("di_factory_or_self_registration", path, number,
                              symbol=symbol, detail="須查證實際註冊實作與生命週期"))
            for rx in (_OPTIONS, _CONFIG):
                for match in rx.finditer(line):
                    key = match.group(1)
                    if config_files:
                        for target in config_files:
                            add(_edge("configuration_reference", path, number,
                                      target=target, symbol=key,
                                      detail="設定來源及環境覆寫尚須核實"))
                    else:
                        add(_edge("configuration_reference", path, number,
                                  symbol=key, detail="設定可能來自環境／秘密管理平台"))
            if _AUTH.search(line):
                for target in startup_files or [None]:
                    add(_edge("endpoint_authorization", path, number, target=target,
                              detail="核對授權屬性、匿名例外及 Middleware 順序"))
            for match in _MIDDLEWARE.finditer(line):
                add(_edge("middleware_pipeline", path, number, symbol=match.group(0).split("(")[0],
                          detail="順序及執行分支須由來源核對"))

    for path in source_paths:
        if not path.lower().endswith(".csproj"):
            continue
        try:
            xml = ET.parse(root / path)
        except (OSError, ET.ParseError):
            continue
        for element in xml.iter():
            if element.tag.rsplit("}", 1)[-1] != "ProjectReference":
                continue
            included = element.get("Include", "").replace("\\", "/")
            target = (Path(path).parent / included)
            # 不接受越出專案的路徑；只連結盤點到的專案檔。
            candidate = (root / target).resolve()
            if candidate.is_relative_to(root.resolve()):
                rel = candidate.relative_to(root.resolve()).as_posix()
                if rel in paths:
                    add(_edge("project_reference", path, 1, target=rel,
                              detail="跨專案依賴，須檢查入口及服務註冊"))

    for source, calls in (call_hints or {}).items():
        if source not in paths:
            continue
        for call in calls:
            line = call.get("line")
            if not isinstance(line, int) or line < 1:
                # Roslyn 呼叫線索以 callsite 欄位為準。
                line = call.get("caller_line")
            if not isinstance(line, int) or line < 1:
                continue
            for match in call.get("possible_targets", []):
                target = match.get("path")
                if target not in paths:
                    continue
                add(_edge("method_call_hint", source, line, target=target,
                          symbol=str(call.get("called_method") or ""),
                          detail=str(call.get("resolution") or "ambiguous"),
                          callsite_id=str(call.get("id") or "")))
    return sorted(result.values(), key=lambda r: (r["source"], r["line"], r["kind"], r["id"]))
