#!/usr/bin/env python3
"""驗證逐檔適用性與來源佐證；檔案清單或單一規則登錄不代表已審查。"""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from functools import lru_cache
from pathlib import Path
from typing import Any

from source_reader import read_source_text
from analysis_candidates import candidate_hits, meaningful_source_excerpt
from review_completion import _template
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
    check_by_id = {check["id"]: check for check in assessment.get("checks", [])}
    findings_by_rule: dict[str, list[dict]] = {}
    for finding in assessment.get("findings", []):
        for rid in finding.get("check_ids", []):
            findings_by_rule.setdefault(rid, []).append(finding)
    verified: dict[str, set[str]] = {}
    errors: list[str] = []
    seen: set[str] = set()
    source_lines: dict[str, list[str]] = {}
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
            source = read_source_text(source_file)[0]
            lines = source.splitlines()
            source_lines[path] = lines
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
            per_category_reasons: dict[str, list[str]] = defaultdict(list)
            for cat in CATEGORIES:
                entry = screening[cat]
                if not isinstance(entry, dict):
                    faults.append(f"{cat}: 篩選紀錄格式錯誤")
                    continue
                reason = entry.get("reason")
                ids = entry.get("rule_ids")
                if not isinstance(reason, str) or len(reason.strip()) < 15:
                    faults.append(f"{cat}: 必須記錄適用或不適用的具體理由")
                else:
                    per_category_reasons[reason.strip()].append(cat)
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
            # 各分類需獨立核對控制責任，不能把同一句空泛理由複製到多個類別。
            for categories in per_category_reasons.values():
                if len(categories) >= 3:
                    faults.append(
                        "category_screening 在 " + "、".join(categories) +
                        " 等類別共用完全相同的理由；須提供各類控制的實際適用性判斷"
                    )
                    break
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
                status = check_by_id.get(rid, {}).get("status")
                if status == "na":
                    faults.append(f"{rid}: 本檔判定適用，但整體檢核卻標為 na")
                if rr.get("result") == "fail":
                    if status == "pass":
                        faults.append(f"{rid}: 逐檔發現問題但整體規則標為 pass")
                    if not findings_by_rule.get(rid):
                        faults.append(f"{rid}: 逐檔發現問題卻未建立 Finding")
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
        # 語意候選僅用來發現「零規則」或遺漏關聯，不自動宣稱規則適用／符合。
        # 確認不適用者可附具體逐條排除理由；不得以十類共用敘述取代。
        signals = {hit["rule_id"]: hit for hit in candidate_hits(path, source)}
        exclusions = row.get("candidate_exclusions", [])
        excluded_candidates: set[str] = set()
        if not isinstance(exclusions, list):
            faults.append("candidate_exclusions 必須是逐條排除理由陣列")
        else:
            for exclusion in exclusions:
                if not isinstance(exclusion, dict):
                    faults.append("candidate_exclusions 內容必須是物件")
                    continue
                rid = exclusion.get("rule_id")
                reason = exclusion.get("reason")
                if not isinstance(rid, str) or rid not in signals or rid in selected:
                    faults.append(f"不合法或已審查的候選排除 {rid!r}")
                    continue
                if rid in excluded_candidates:
                    faults.append(f"{rid}: 候選排除理由重複")
                excluded_candidates.add(rid)
                if not isinstance(reason, str) or len(reason.strip()) < 40:
                    faults.append(f"{rid}: 候選排除須具體說明已核對的控制責任及不適用原因（至少 40 字）")
        for rid in sorted(signals.keys() - selected - excluded_candidates):
            hit = signals[rid]
            faults.append(
                f"{rid}: 第 {hit['line']} 行有「{hit['signal']}」安全規則候選，"
                "但未逐檔檢核；請追查呼叫鏈並加入 rule_reviews／inspected_paths，"
                "或在 candidate_exclusions 逐條說明真正不適用的原因"
            )
        if faults:
            errors.extend(f"{path}: {fault}" for fault in faults)
        else:
            verified[path] = recorded

    # 批次模板只變換行數或 ID 不能代替真實的逐檔分析。
    # 這不是最低關聯規則數門檻：一個檔案可以只有零或一個適用規則。
    if len(rows) >= 30:
        template_groups: dict[str, dict[str, set[str]]] = {
            "逐檔摘要": defaultdict(set),
            "逐檔規則結論": defaultdict(set),
        }
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("path"), str):
                continue
            summary = row.get("summary")
            if isinstance(summary, str):
                template = _template(summary.replace(row["path"], "<PATH>"))
                template_groups["逐檔摘要"][template].add(row["path"])
            for item in row.get("rule_reviews", []):
                if isinstance(item, dict) and isinstance(item.get("reason"), str):
                    template = _template(item["reason"].replace(row["path"], "<PATH>"))
                    template_groups["逐檔規則結論"][template].add(row["path"])
        threshold = max(15, (len(rows) + 7) // 8)  # 八分之一以上高度同質輸出需要重新核對
        for kind, groups in template_groups.items():
            for paths in groups.values():
                if len(paths) >= threshold:
                    errors.append(
                        f"{len(paths)}/{len(rows)} 個檔案共用相同的{kind}模板"
                        "（僅數字不同），不能宣稱已逐檔完成安全分析；例："
                        + "、".join(sorted(paths)[:3])
                    )
                    break

    # 來源註解、using、空括號、純方法宣告不是有效的安全控制完成證據。
    # 此處使用真實檔案內容（非 evidence.description 字串）驗證。
    for check in assessment.get("checks", []):
        rid = check.get("id", "?")
        execution = check.get("execution") or {}
        if execution.get("state") != "completed" or check.get("status") not in ("pass", "fail", "review"):
            continue
        source_evidence = [e for e in check.get("evidence", [])
                           if isinstance(e, dict) and e.get("kind") == "source"]
        non_source_evidence = any(
            isinstance(e, dict) and e.get("kind") != "source"
            and (e.get("path") or e.get("artifact_id"))
            for e in check.get("evidence", [])
        )
        meaningful = False
        for ev in source_evidence:
            path = ev.get("path")
            if path not in expected:
                continue  # 其他來源路徑錯誤由 strict source 驗證器處理
            if path not in completed.get(rid, set()):
                errors.append(f"{rid}: 來源證據 {path} 未列入 execution.inspected_paths")
            lines = source_lines.get(path)
            start, end = ev.get("line_start"), ev.get("line_end")
            if (lines is None or not isinstance(start, int) or isinstance(start, bool)
                    or not isinstance(end, int) or isinstance(end, bool)
                    or start < 1 or end < start or end > len(lines)):
                continue  # 缺行號由既有 schema 和來源驗證處理
            if meaningful_source_excerpt(path, lines[start - 1:end]):
                meaningful = True
        if source_evidence and not meaningful and not non_source_evidence:
            errors.append(
                f"{rid}: 完成證據僅包含 using／註解／宣告／空結構等無效來源片段；"
                "須以實際控制實作或可追溯外部工件重新核對"
            )

    # 禁止舊版批次掛路徑：每筆 inspected_paths 都須有逐檔實證與對應規則。
    orphaned = []
    for rid, paths in completed.items():
        for path in paths & expected:
            if rid not in verified.get(path, set()):
                orphaned.append(f"{rid} → {path}")
    if orphaned:
        errors.append(f"存在 {len(orphaned)} 筆未經逐檔驗證的 inspected_paths（前 10 筆）：{'; '.join(sorted(orphaned)[:10])}")
    return verified, errors
