#!/usr/bin/env python3
"""Untrusted, read-only worker result verifier. Never writes official review evidence."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from source_reader import read_source_text, source_digest
from file_review_integrity import CATEGORIES

VERSION = 1
SHA = re.compile(r"^[0-9a-f]{64}$")
RULE = re.compile(r"^(AC|AU|IN|CR|EH|LG|DP|PD|BC|SI)-[0-9]{2}$")
# Deliberately reject common credential patterns in *any* serialized result field.
SECRET = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    r"\bAKIA[0-9A-Z]{16}\b|"
    r"\b(?:Bearer\s+[A-Za-z0-9._~+/-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,})\b|"
    r"(?i:password|client_secret|api[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}['\"]"
)
ALLOWED_ROOT = {"schema_version", "task_id", "worker_id", "snapshot_fingerprint",
                "status", "files", "issues", "tokens_used"}
ALLOWED_FILE = {"path", "sha256", "reviewed_ranges", "category_screening",
                "rule_states", "unresolved_symbols", "findings"}
ALLOWED_FINDING = {"rule_id", "path", "line_start", "line_end",
                   "sink", "root_cause", "summary", "evidence"}
ALLOWED_PROOF = {"path", "line_start", "line_end", "summary"}


def digest(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":")).encode("utf-8")).hexdigest()


def _text(value: Any, minimum: int = 1, maximum: int = 2000) -> bool:
    return isinstance(value, str) and minimum <= len(value.strip()) <= maximum


def _range(value: Any, line_count: int) -> bool:
    return (isinstance(value, dict) and set(value) == {"start", "end"}
            and type(value["start"]) is int and type(value["end"]) is int
            and 1 <= value["start"] <= value["end"] <= line_count)


def _proof(root: Path, value: Any, hashes: dict, lines: dict[str, int],
           *, anchored: str | None = None) -> bool:
    if not isinstance(value, dict) or not set(value) <= ALLOWED_PROOF:
        return False
    path = value.get("path")
    if not isinstance(path, str) or path not in hashes or (anchored is not None and path != anchored):
        return False
    return (type(value.get("line_start")) is int
            and type(value.get("line_end")) is int
            and 1 <= value["line_start"] <= value["line_end"] <= lines[path]
            and _text(value.get("summary"), 12, 1000))


def validate_worker_result(root: Path, task: dict, result: Any,
                           hashes: dict[str, str], *, require_complete: bool = True
                           ) -> list[str]:
    """Return bounded errors; success is NOT a security verdict or completed review."""
    errors: list[str] = []
    if not isinstance(result, dict):
        return ["worker result 必須是 JSON object"]
    if set(result) != ALLOWED_ROOT:
        errors.append("worker result 欄位不符封閉契約")
    if (result.get("schema_version") != VERSION
            or result.get("task_id") != task.get("task_id")
            or result.get("worker_id") != task.get("worker_id")
            or result.get("snapshot_fingerprint") != task.get("snapshot_fingerprint")):
        errors.append("worker 任務、版本或快照識別不一致")
    status = result.get("status")
    if status not in {"completed", "failed"}:
        errors.append("worker status 無效")
    if type(result.get("tokens_used")) is not int or result["tokens_used"] < 0:
        errors.append("tokens_used 必須為非負整數（無法量測時填 0，不得估算）")
    if not isinstance(result.get("issues"), list) or any(
            not _text(issue, 5, 1000) for issue in result.get("issues", [])):
        errors.append("issues 格式不合法")
    raw = json.dumps(result, ensure_ascii=False)
    if SECRET.search(raw):
        errors.append("worker 結果疑似包含機敏資訊，不得儲存或整合")
    if len(raw) > 2_000_000:
        errors.append("worker 結果超出安全大小限制")
    files = result.get("files")
    if not isinstance(files, list):
        return errors + ["files 必須為陣列"]
    owned = {entry["path"]: entry for entry in task.get("assigned_paths", [])}
    paths = [row.get("path") for row in files if isinstance(row, dict)]
    if (len(paths) != len(files) or any(not isinstance(p, str) for p in paths)
            or len(set(paths)) != len(paths)):
        return errors + ["檔案缺少合法 path 或重複"]
    if not set(paths) <= set(owned):
        errors.append("worker 回報未授權的分片路徑")
    if status == "completed" and require_complete and set(paths) != set(owned):
        errors.append("completed 必須涵蓋本次所有分配來源")
    known_lines: dict[str, int] = {}
    for row in files:
        if not isinstance(row, dict) or set(row) != ALLOWED_FILE:
            errors.append("檔案結果欄位不符契約")
            continue
        path = row.get("path")
        if path not in owned or path not in hashes:
            continue
        source = (root.resolve() / path).resolve()
        if not source.is_relative_to(root.resolve()) or not source.is_file() or source.is_symlink():
            errors.append("來源路徑不安全")
            continue
        raw_source = source.read_bytes()
        if (source_digest(raw_source) != hashes[path]
                or row.get("sha256") != hashes[path]
                or owned[path].get("sha256") != hashes[path]):
            errors.append(f"{path}: 來源 SHA256 不一致")
            continue
        try:
            text = read_source_text(source, raw=raw_source)[0]
        except (UnicodeError, OSError):
            errors.append(f"{path}: 無法解碼來源")
            continue
        count = len(text.splitlines())
        known_lines[path] = count
        spans = row.get("reviewed_ranges")
        if not isinstance(spans, list) or not all(_range(x, count) for x in spans):
            errors.append(f"{path}: 閱讀行範圍無效")
        elif status == "completed" and require_complete:
            end = 0
            for span in sorted(spans, key=lambda x: x["start"]):
                if span["start"] > end + 1:
                    break
                end = max(end, span["end"])
            if end != count:
                errors.append(f"{path}: 未覆蓋來源所有行（僅自我聲明，非已驗證人工閱讀）")
        categories = row.get("category_screening")
        if (not isinstance(categories, dict) or set(categories) != set(CATEGORIES)
                or any(not isinstance(v, dict) or set(v) != {"status", "reason"}
                       or v["status"] not in {"candidate", "not_applicable", "unresolved"}
                       or not _text(v["reason"], 12, 600)
                       for v in categories.values())):
            errors.append(f"{path}: 十類逐檔篩選缺失")
        states = row.get("rule_states")
        if not isinstance(states, list):
            errors.append(f"{path}: rule_states 缺失")
            states = []
        seen: set[str] = set()
        for rule in states:
            if not isinstance(rule, dict) or set(rule) != {"rule_id", "status", "reason", "evidence"}:
                errors.append(f"{path}: 規則狀態欄位無效")
                continue
            rid = rule.get("rule_id")
            if (not isinstance(rid, str) or not RULE.fullmatch(rid)
                    or rid in seen or rule.get("status") not in {"hit", "not_applicable", "unassessed"}
                    or not _text(rule.get("reason"), 12, 1000)
                    or not isinstance(rule.get("evidence"), list)):
                errors.append(f"{path}: 規則狀態無效或重複")
            if isinstance(rid, str):
                seen.add(rid)
            for proof in rule.get("evidence", []) if isinstance(rule.get("evidence"), list) else []:
                if not _proof(root, proof, hashes, {path: count}, anchored=path):
                    errors.append(f"{path}: 規則證據行號或格式無效")
        required_candidates = set(owned[path].get("candidate_rule_ids", []))
        if not required_candidates <= seen:
            errors.append(f"{path}: 缺少候選規則的逐條 hit/not_applicable/unassessed 回報")
        symbols = row.get("unresolved_symbols")
        if not isinstance(symbols, list):
            errors.append(f"{path}: 未解符號格式無效")
            symbols = []
        for sym in symbols:
            if (not isinstance(sym, dict) or set(sym) != {"name", "path", "line_start", "reason"}
                    or sym.get("path") != path or not _text(sym.get("name"), 1, 200)
                    or type(sym.get("line_start")) is not int
                    or not 1 <= sym["line_start"] <= count
                    or not _text(sym.get("reason"), 12, 600)):
                errors.append(f"{path}: 未解跨分片符號無效")
        findings = row.get("findings")
        if not isinstance(findings, list):
            errors.append(f"{path}: Finding 候選格式無效")
            findings = []
        for finding in findings:
            if not isinstance(finding, dict) or set(finding) != ALLOWED_FINDING:
                errors.append(f"{path}: Finding 欄位不符契約")
                continue
            if (finding.get("path") != path or not isinstance(finding.get("rule_id"), str)
                    or not RULE.fullmatch(finding["rule_id"])
                    or not _text(finding.get("sink"), 2, 200)
                    or not _text(finding.get("root_cause"), 12, 1000)
                    or not _text(finding.get("summary"), 12, 1000)
                    or not isinstance(finding.get("evidence"), list)
                    or not finding["evidence"]):
                errors.append(f"{path}: Finding 定位或說明不完整")
            if (type(finding.get("line_start")) is not int
                    or type(finding.get("line_end")) is not int
                    or not 1 <= finding["line_start"] <= finding["line_end"] <= count):
                errors.append(f"{path}: Finding 行號無效")
            for proof in finding.get("evidence", []) if isinstance(finding.get("evidence"), list) else []:
                if not _proof(root, proof, hashes, {path: count}, anchored=path):
                    errors.append(f"{path}: Finding 證據無法定位；跨檔證據須由主代理獨立查證")
    if status == "completed" and any(
            row.get("unresolved_symbols") for row in files if isinstance(row, dict)):
        errors.append("存在未解跨分片符號，須由主代理補派與結案")
    if status == "failed" and not result.get("issues"):
        errors.append("failed 必須提供原因")
    return errors[:80]


def finding_key(finding: dict) -> str:
    """候選去重線索；不同入口或相同根因仍需人工裁決。"""
    return digest([finding.get(k) for k in
                   ("rule_id", "path", "line_start", "line_end", "sink", "root_cause")])
