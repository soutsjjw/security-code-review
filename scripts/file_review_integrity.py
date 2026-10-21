#!/usr/bin/env python3
"""驗證逐檔適用性與來源佐證；檔案清單或單一規則登錄不代表已審查。"""
from __future__ import annotations

import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from source_reader import read_source_text
from scope_inventory import relative_path

CATEGORIES = ("AC", "AU", "IN", "CR", "EH", "LG", "DP", "PD", "BC", "SI")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


@lru_cache(maxsize=1)
def _master_rules() -> dict[str, str]:
    rules = json.loads((Path(__file__).resolve().parents[1] / "rules.json").read_text("utf-8"))["rules"]
    return {rule["id"]: rule["id"].split("-")[0] for rule in rules}


def verified_file_rule_reviews(
    assessment: dict[str, Any], root: Path, expected: set[str],
) -> tuple[dict[str, set[str]], list[str]]:
    """只接受摘要、雜湊、10 類逐檔篩選、規則行號與 completed 紀錄均一致的檔案。

    自陳證據無法證明 Agent 確實閱讀；此檢查至少阻擋舊版只填 inspected_paths
    或依檔名批次掛上單一規則後即聲稱 100% 覆蓋的情形。
    """
    rows = assessment.get("file_reviews")
    if not isinstance(rows, list):
        if not expected and not any((c.get("execution") or {}).get("inspected_paths") for c in assessment.get("checks", [])):
            return {}, []  # 空的受測工作樹：沒有來源可逐檔記錄。
        return {}, ["缺少 file_reviews：必須逐檔完成 10 類規則篩選與可追溯的規則審查，不可沿用 inspected_paths 宣稱完成"]
    rules = _master_rules()
    completed: dict[str, set[str]] = {}
    for check in assessment.get("checks", []):
        execution = check.get("execution") or {}
        if execution.get("state") == "completed":
            completed[check["id"]] = set(execution.get("inspected_paths") or [])
    verified: dict[str, set[str]] = {}
    errors: list[str] = []
    seen: set[str] = set()
    for index, row in enumerate(rows):
        label = f"file_reviews[{index}]"
        if not isinstance(row, dict):
            errors.append(f"{label}: 逐檔紀錄必須是物件")
            continue
        raw = row.get("path")
        try:
            path = relative_path(root, raw)
        except (ValueError, TypeError) as exc:
            errors.append(f"{label}: {exc}")
            continue
        if path in seen:
            errors.append(f"{path}: file_reviews 重複路徑")
            continue
        seen.add(path)
        if path not in expected:
            errors.append(f"{path}: 來源不存在、已排除或非必要審查來源檔")
            continue
        faults: list[str] = []
        source_file = root / path
        try:
            content = source_file.read_bytes()
            lines = read_source_text(source_file)[0].splitlines()
        except (OSError, UnicodeError) as exc:
            errors.append(f"{path}: 無法安全閱讀來源：{exc}")
            continue
        digest = row.get("sha256")
        if not isinstance(digest, str) or not SHA256.fullmatch(digest) or digest != hashlib.sha256(content).hexdigest():
            faults.append("sha256 缺失、不合法或來源檔已異動；必須重新審查")
        if not isinstance(row.get("summary"), str) or len(row["summary"].strip()) < 20:
            faults.append("須記錄至少 20 字的逐檔實際分析摘要")
        methods = row.get("methods")
        if not isinstance(methods, list) or not methods or any(not isinstance(m, str) or len(m.strip()) < 3 for m in methods):
            faults.append("缺少實際逐檔檢查方法")
        screening = row.get("category_screening")
        selected: set[str] = set()
        if not isinstance(screening, dict) or set(screening) != set(CATEGORIES):
            faults.append("category_screening 必須逐一篩選全部 10 類規則")
        else:
            for cat in CATEGORIES:
                entry = screening[cat]
                if not isinstance(entry, dict):
                    faults.append(f"{cat}: 篩選紀錄格式錯誤")
                    continue
                reason = entry.get("reason")
                ids = entry.get("rule_ids")
                if not isinstance(reason, str) or len(reason.strip()) < 15:
                    faults.append(f"{cat}: 必須記錄適用或不適用的具體理由")
                if not isinstance(ids, list) or len(ids) != len(set(map(str, ids))):
                    faults.append(f"{cat}: rule_ids 缺失或重複")
                    continue
                for rid in ids:
                    if not isinstance(rid, str) or rules.get(rid) != cat:
                        faults.append(f"{cat}: 不合法規則 ID {rid!r}")
                    elif rid in selected:
                        faults.append(f"{rid}: 跨類別重複登錄")
                    else:
                        selected.add(rid)
        rule_reviews = row.get("rule_reviews")
        recorded: set[str] = set()
        if not isinstance(rule_reviews, list):
            faults.append("rule_reviews 必須是逐條實際檢查紀錄")
        else:
            for rr in rule_reviews:
                if not isinstance(rr, dict):
                    faults.append("rule_reviews 含非物件紀錄")
                    continue
                rid = rr.get("rule_id")
                if not isinstance(rid, str) or rid not in rules:
                    faults.append(f"rule_reviews 含未知規則：{rid!r}")
                    continue
                if rid in recorded:
                    faults.append(f"{rid}: 同檔案重複規則")
                recorded.add(rid)
                if rr.get("result") not in ("pass", "fail", "review"):
                    faults.append(f"{rid}: 缺少本檔檢核結果")
                if not isinstance(rr.get("reason"), str) or len(rr["reason"].strip()) < 20:
                    faults.append(f"{rid}: 缺少具體檢核結果與判斷依據")
                start, end = rr.get("line_start"), rr.get("line_end")
                if (not isinstance(start, int) or isinstance(start, bool) or
                    not isinstance(end, int) or isinstance(end, bool) or
                    start < 1 or end < start or end > len(lines)):
                    faults.append(f"{rid}: 佐證行號不存在或順序錯誤")
                if rid not in completed or path not in completed[rid]:
                    faults.append(f"{rid}: 未同步登錄 completed 規則的 execution.inspected_paths")
        if recorded != selected:
            faults.append("category_screening.rule_ids 與逐條 rule_reviews 不一致")
        if faults:
            errors.extend(f"{path}: {fault}" for fault in faults)
        else:
            verified[path] = recorded

    # 禁止舊版批次掛路徑：每筆 inspected_paths 都須有逐檔實證與對應規則。
    orphaned = []
    for rid, paths in completed.items():
        for path in paths & expected:
            if rid not in verified.get(path, set()):
                orphaned.append(f"{rid} → {path}")
    if orphaned:
        errors.append(f"存在 {len(orphaned)} 筆未經逐檔驗證的 inspected_paths（前 10 筆）：{'; '.join(sorted(orphaned)[:10])}")
    return verified, errors
