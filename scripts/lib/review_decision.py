#!/usr/bin/env python3
"""70 項判定方式與證據強度守門：拒絕看似有行號、實際無控制證據的假性完成。

本模組只做保守的機械辨識；不能用字串比對取代對程式碼、呼叫鏈及政策的實際分析。
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from source_reader import read_source_text

ROOT = Path(__file__).resolve().parents[2]
DECISION_MATRIX = ROOT / "policies" / "review-decision-matrix.json"
EXTERNAL_KINDS = frozenset({"deployment", "operating_record", "policy", "scan", "test", "interview"})
CODE_SUFFIXES = frozenset({".cs", ".razor", ".cshtml", ".js", ".jsx", ".ts", ".tsx", ".vue", ".vb", ".fs", ".py"})
# 僅排除「沒有控制語意」的片段；不以關鍵字匹配宣稱通過或不符合。
BOILERPLATE = (
    re.compile(r"^(?:global\s+)?using\s+[\w.]+\s*;$"),
    re.compile(r"^namespace\s+[\w.]+\s*[;{]?$"),
    re.compile(r"^(?:var\s+\w+\s*=\s*)?WebApplication\.CreateBuilder\(args\);$"),
    re.compile(r"^\s*(?:\{|\}|;|,|\(|\))+\s*$"),
    re.compile(r"^\s*(?://|/\*|\*|#|<!--|-->)"),
    re.compile(r"^(?:(?:public|private|protected|internal|static|readonly|required|virtual|override)\s+)*"
               r"[\w<>?,\[\].]+\s+\w+\s*\{\s*(?:get;\s*)?(?:set;\s*)?(?:init;\s*)?\}\s*;?$"),
    re.compile(r"^[\w.?!]+\s*,?$"),  # 單獨參數、欄位名稱或物件識別符
)
GENERIC_DECISIONS = (
    "所以不能把靜態檢查推論成完整符合，保留 review",
    "目前缺少需補動態測試結果及邊界案例紀錄",
    "目前缺少需補正式部署設定與反向代理／主機工件",
    "目前缺少需補相依套件弱點掃描或 SBOM 工件",
    "控制邏輯足以支持本次靜態判定，未確認到可繞過的缺陷",
    "結論依靜態證據與外部證據缺口判定",
)


def load_decision_matrix() -> dict[str, dict[str, str]]:
    payload = json.loads(DECISION_MATRIX.read_text(encoding="utf-8"))
    rules = payload["rules"]
    if len(rules) != 70 or any(v.get("mode") not in {"static", "hybrid", "external"} for v in rules.values()):
        raise ValueError("判定矩陣須完整列出 70 項規則及有效檢核方式")
    return rules


def _meaningful_excerpt(lines: list[str]) -> bool:
    for line in lines:
        stripped = line.strip()
        if stripped and not any(pattern.match(stripped) for pattern in BOILERPLATE):
            return True
    return False


def _is_weak_source_evidence(ev: dict[str, Any], source_root: Path) -> bool | None:
    path = ev.get("path")
    if not isinstance(path, str) or not path.strip() or Path(path).suffix.lower() not in CODE_SUFFIXES:
        return None
    start, end = ev.get("line_start"), ev.get("line_end")
    if not isinstance(start, int) or not isinstance(end, int) or start <= 0 or end < start:
        return None
    root = source_root.resolve()
    target = (root / path).resolve()
    if not target.is_relative_to(root) or not target.is_file():
        return None  # 路徑真實性由來源驗證器處理
    try:
        source, _ = read_source_text(target)
    except (OSError, UnicodeError, ValueError):
        return None
    lines = source.splitlines()
    if end > len(lines):
        return None
    return not _meaningful_excerpt(lines[start - 1:end])


def decision_quality_errors(
    checks: list[dict[str, Any]], *, source_root: Path | None = None
) -> list[str]:
    """回傳必須重審的規則；從不自動把 review 改 pass 或 fail。"""
    matrix = load_decision_matrix()
    errors: list[str] = []
    for check in checks:
        rid = str(check.get("id", ""))
        if (check.get("execution") or {}).get("state") != "completed" or rid not in matrix:
            continue
        mode = matrix[rid]["mode"]
        status = check.get("status")
        reason = str(check.get("decision_reason", ""))
        evidence = [ev for ev in check.get("evidence", []) if isinstance(ev, dict)]
        if any(phrase in reason or any(phrase in str(ev.get("description", "")) for ev in evidence)
               for phrase in GENERIC_DECISIONS):
            errors.append(f"{rid}: 套用制式結論／外部缺口，須核對本規則的控制流程與必要證據")
        # static 是主要可由來源判定，不表示永遠不需外部佐證；
        # 具體外部缺口應允許 review，僅制式理由由上方攔截。
        if status == "pass" and mode == "external" and source_root is not None:
            real_external = any(
                ev.get("kind") in EXTERNAL_KINDS and (ev.get("artifact_id") or ev.get("path"))
                for ev in evidence
            )
            # 可版本控制的真實部署/主機組態也可支援，但一般業務程式碼不可。
            config_proof = any(
                ev.get("kind") == "configuration" and isinstance(ev.get("path"), str)
                and Path(ev["path"]).suffix.lower() not in CODE_SUFFIXES
                and (ev.get("artifact_id") or ev.get("line_start"))
                for ev in evidence
            )
            if not (real_external or config_proof):
                errors.append(f"{rid}: 外部／制度控制不可以一般業務原始碼宣稱 pass；須取得本規則的部署、制度或測試證據")
        if status in {"pass", "fail", "review"} and source_root is not None:
            source_evidence = [
                ev for ev in evidence if ev.get("kind") in {"source", "configuration"}
            ]
            inspected = [_is_weak_source_evidence(ev, source_root) for ev in source_evidence]
            # 只有純宣告／using／namespace／單一欄位等證據且沒有獨立工件：應重新查核。
            if inspected and all(v is True for v in inspected) and not any(
                ev.get("kind") in EXTERNAL_KINDS and (ev.get("path") or ev.get("artifact_id"))
                for ev in evidence
            ):
                errors.append(f"{rid}: 來源證據只含宣告／using／namespace／單獨識別符，不能證明控制有效或已完成核查")
    return errors
