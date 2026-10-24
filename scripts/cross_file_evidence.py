#!/usr/bin/env python3
"""跨檔證據守門：驗證控制鏈節點與索引關聯的可追溯性，不自行作安全判定。"""
from __future__ import annotations

from collections import Counter
import re
from pathlib import Path
from typing import Any

from review_decision import _is_weak_source_evidence, load_decision_matrix
from source_reader import read_source_text

CONTRACT_VERSION = 1
NODE_ROLES = frozenset({"entry", "enforcement", "operation", "configuration", "support"})
EDGE_DISMISS_BASES = frozenset({"unrelated_rule", "different_entry", "unrelated_symbol",
                               "not_invoked", "alternative_implementation"})
CALL_EXCLUDE_BASES = EDGE_DISMISS_BASES
BINDINGS = frozenset({"direct", "interface_dispatch", "dependency_injection",
                      "configuration", "middleware", "other_verified"})
BOUNDARIES = frozenset({"connected", "single_file"})


def _reason_template(reason: str) -> str:
    """忽略規則編號、位置和數字後偵測大量相同的跨檔排除理由。"""
    normalized = reason.casefold()
    normalized = re.sub(r"\b[a-z]{2}-\d{2}\b", "<rule>", normalized)
    normalized = re.sub(r"\b[a-z0-9_./\\-]+\.(?:cs|csproj|json|cshtml)\b",
                        "<path>", normalized)
    normalized = re.sub(r"\b\d+\b", "<number>", normalized)
    return " ".join(normalized.split())


def _point_errors(root: Path, point: Any, known: set[str],
                  inspected: set[str], examined: set[str], label: str) -> list[str]:
    if not isinstance(point, dict):
        return [f"{label}: 來源證據必須是物件"]
    path, lo, hi = point.get("path"), point.get("line_start"), point.get("line_end")
    if not isinstance(path, str) or path not in known or path not in inspected or path not in examined:
        return [f"{label}: 證據路徑須屬於快照、已審查與實際檢閱的來源"]
    if type(lo) is not int or type(hi) is not int or lo < 1 or hi < lo:
        return [f"{label}: 來源行號無效"]
    try:
        lines = read_source_text(root / path)[0].splitlines()
    except (OSError, UnicodeError, ValueError):
        return [f"{label}: 無法重新讀取來源"]
    if hi > len(lines):
        return [f"{label}: 行號超出實際來源"]
    if _is_weak_source_evidence(point, root) is True:
        return [f"{label}: 引用只有宣告／註解等薄弱來源，不能作為控制鏈證據"]
    if not any(line.strip() and not line.lstrip().startswith(("//", "/*", "*", "#"))
               for line in lines[lo - 1:hi]):
        return [f"{label}: 缺少實際程式碼或設定內容"]
    return []


def trace_errors(target: Path, index: dict, snapshot: dict, check: dict,
                 closure: dict, scope: str) -> list[str]:
    """只針對新版索引：偽造的路徑或一律排除呼叫點不得構成結案證據。"""
    if index.get("cross_file_evidence_version") != CONTRACT_VERSION:
        return []
    rid = check.get("id", "")
    status = check.get("status")
    matrix = load_decision_matrix().get(rid, {})
    formal = check.get("evidence") or []
    has_source = any(isinstance(e, dict) and e.get("kind") in {"source", "configuration"}
                     for e in formal)
    # 純外部的專案責任或真實 N/A 不虛構不存在的程式碼控制鏈。
    required = (scope == "cross_file" and status != "na") or (
        scope == "project" and has_source and status in {"pass", "fail", "review"}
        and matrix.get("mode") != "external"
    )
    trace = closure.get("control_trace")
    if not required and trace is None:
        return []
    if not isinstance(trace, dict):
        return [f"{rid}: Q2 缺少實際入口、控制執行與受保護操作的 control_trace"]

    known = set(snapshot.get("source_hashes") or {})
    inspected = (check.get("execution") or {}).get("inspected_paths") or []
    inspected = set(p for p in inspected if isinstance(p, str))
    examined = closure.get("examined_paths") or []
    examined = set(p for p in examined if isinstance(p, str))
    issues: list[str] = []
    nodes = trace.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        return [f"{rid}: Q2 control_trace.nodes 不得為空；應列出實際程式碼節點"]
    roles: set[str] = set()
    paths: set[str] = set()
    for i, node in enumerate(nodes):
        label = f"{rid}: Q2 控制鏈節點[{i}]"
        if not isinstance(node, dict):
            issues.append(f"{label} 必須為物件")
            continue
        role = node.get("role")
        if not isinstance(role, str) or role not in NODE_ROLES:
            issues.append(f"{label} 缺少明確入口／控制／操作／設定角色")
        else:
            roles.add(role)
        note = node.get("reason")
        if not isinstance(note, str) or len(note.strip()) < 24:
            issues.append(f"{label} 缺少實際控制分支及責任說明")
        issues.extend(_point_errors(target, node, known, inspected, examined, label))
        if isinstance(node.get("path"), str):
            paths.add(node["path"])
    if not roles & {"enforcement", "operation"}:
        issues.append(f"{rid}: Q2 控制鏈缺少實際控制執行或受保護操作節點")
    source_formal = [e for e in formal if isinstance(e, dict)
                     and e.get("kind") in {"source", "configuration"}
                     and type(e.get("line_start")) is int and type(e.get("line_end")) is int]
    if source_formal and not any(
        e.get("path") == n.get("path") and e["line_start"] <= n.get("line_end", -1)
        and e["line_end"] >= n.get("line_start", -1)
        for e in source_formal for n in nodes if isinstance(n, dict)
        and type(n.get("line_start")) is int and type(n.get("line_end")) is int
    ):
        issues.append(f"{rid}: Q2 控制鏈與正式檢核來源證據無交集")

    boundary = trace.get("boundary")
    if not isinstance(boundary, str) or boundary not in BOUNDARIES:
        issues.append(f"{rid}: Q2 控制鏈 boundary 須為 connected 或 single_file")
    if boundary == "single_file":
        reason = trace.get("boundary_reason")
        if len(paths) != 1 or not isinstance(reason, str) or len(reason.strip()) < 30:
            issues.append(f"{rid}: Q2 單檔控制鏈必須有唯一來源及具體的跨檔排除依據")
    edges_by_id = {e.get("id"): e for e in (index.get("typed_relationships") or [])
                   if isinstance(e, dict) and isinstance(e.get("id"), str)}
    relationships = trace.get("relationships")
    if not isinstance(relationships, list):
        issues.append(f"{rid}: Q2 control_trace.relationships 必須為陣列")
        relationships = []
    confirmed: set[str] = set()
    connected: dict[str, set[str]] = {p: set() for p in paths}
    call_reviews = closure.get("callsite_reviews") or {}
    for i, rel in enumerate(relationships):
        label = f"{rid}: Q2 已確認關聯[{i}]"
        if not isinstance(rel, dict):
            issues.append(f"{label} 必須為物件")
            continue
        eid = rel.get("relationship_id")
        edge = edges_by_id.get(eid) if isinstance(eid, str) else None
        if not isinstance(eid, str) or edge is None or eid in confirmed:
            issues.append(f"{label} ID 不存在或重複")
            continue
        confirmed.add(eid)
        src, dest = edge.get("source"), edge.get("target")
        if src not in paths or dest not in paths or not dest or src == dest:
            issues.append(f"{label} 必須連結兩個已實際閱讀的控制鏈節點")
        else:
            connected[src].add(dest)
            connected[dest].add(src)
        proof = rel.get("evidence")
        issues.extend(_point_errors(target, proof, known, inspected, examined, label))
        line = edge.get("line")
        if (not isinstance(proof, dict) or proof.get("path") != src
                or type(proof.get("line_start")) is not int
                or type(proof.get("line_end")) is not int
                or type(line) is not int
                or not (proof["line_start"] <= line <= proof["line_end"])):
            issues.append(f"{label} 來源行號必須涵蓋索引中的實際呼叫／註冊位置")
        reason = rel.get("reason")
        if not isinstance(reason, str) or len(reason.strip()) < 24:
            issues.append(f"{label} 缺少來源及實際目標的核對理由")
        if edge.get("kind") == "method_call_hint":
            review = call_reviews.get(edge.get("callsite_id")) if isinstance(call_reviews, dict) else None
            if (not isinstance(review, dict) or review.get("status") != "verified"
                    or dest not in (review.get("selected_targets") or [])):
                issues.append(f"{label} Method 呼叫未有 verified 目標核對")

    examined_ids = closure.get("examined_relationship_ids")
    if not isinstance(examined_ids, list) or any(not isinstance(x, str) for x in examined_ids) or len(examined_ids) != len(confirmed) or set(x for x in examined_ids if isinstance(x, str)) != confirmed:
        issues.append(f"{rid}: Q2 examined_relationship_ids 必須與有證據的控制鏈關聯完全一致")
    if boundary == "connected":
        if len(paths) < 2 or not confirmed:
            issues.append(f"{rid}: Q2 跨檔控制鏈需要至少兩檔與一筆已證實關聯")
        elif connected:
            core = {n.get("path") for n in nodes if isinstance(n, dict)
                    and n.get("role") in {"entry", "enforcement", "operation"}
                    and isinstance(n.get("path"), str)}
            reached: set[str] = set()
            queue = [next(iter(core or paths))]
            while queue:
                p = queue.pop()
                if p in reached:
                    continue
                reached.add(p)
                queue.extend(connected.get(p, ()) - reached)
            if not core <= reached:
                issues.append(f"{rid}: Q2 核心入口、控制與操作節點未形成可追溯的跨檔關聯")
    if boundary == "single_file" and confirmed:
        issues.append(f"{rid}: Q2 單檔控制鏈不可同時宣稱跨檔關聯已確認")

    dismissals = closure.get("dismissed_relationships") or {}
    if isinstance(dismissals, dict):
        for eid, record in dismissals.items():
            if eid in confirmed:
                issues.append(f"{rid}: Q2 關聯 {eid} 不可同時確認與排除")
            if eid not in edges_by_id:
                continue  # 原有 closure_errors 已檢查索引中是否存在。
            if not isinstance(record, dict):
                issues.append(f"{rid}: Q2 排除關聯 {eid} 必須附具體分類及來源證據")
                continue
            if not isinstance(record.get("basis"), str) or record["basis"] not in EDGE_DISMISS_BASES:
                issues.append(f"{rid}: Q2 排除關聯 {eid} 缺少可核對的排除類型")
            if not isinstance(record.get("reason"), str) or len(record["reason"].strip()) < 24:
                issues.append(f"{rid}: Q2 排除關聯 {eid} 缺少具體理由")
            edge = edges_by_id[eid]
            proof = record.get("evidence")
            issues.extend(_point_errors(target, proof, known, inspected, examined,
                                        f"{rid}: Q2 排除關聯 {eid}"))
            line = edge.get("line")
            if not isinstance(proof, dict) or proof.get("path") != edge.get("source") or (
                type(proof.get("line_start")) is not int or
                type(proof.get("line_end")) is not int or type(line) is not int or
                not proof["line_start"] <= line <= proof["line_end"]
            ):
                issues.append(f"{rid}: Q2 排除關聯 {eid} 證據未指向候選來源行")
    if isinstance(call_reviews, dict):
        hints = {c.get("id"): (p, c) for p, rows in
                 (index.get("cross_file_call_hints") or {}).items()
                 for c in rows if isinstance(c, dict) and isinstance(c.get("id"), str)}
        excluded_reasons = []
        for cid, row in call_reviews.items():
            if not isinstance(row, dict):
                continue
            call = hints.get(cid)
            if call is None:
                continue  # 原有 closure_errors 已檢查未知呼叫點。
            origin, info = call
            proof = row.get("evidence")
            issues.extend(_point_errors(target, proof, known, inspected, examined,
                                        f"{rid}: Q2 呼叫點 {cid}"))
            line = info.get("line", info.get("caller_line"))
            if (not isinstance(proof, dict) or proof.get("path") != origin
                or type(proof.get("line_start")) is not int
                or type(proof.get("line_end")) is not int or type(line) is not int
                or not proof["line_start"] <= line <= proof["line_end"]):
                issues.append(f"{rid}: Q2 呼叫點 {cid} 缺少實際呼叫位置的來源證據")
            if row.get("status") == "excluded":
                if not isinstance(row.get("exclusion_basis"), str) or row["exclusion_basis"] not in CALL_EXCLUDE_BASES:
                    issues.append(f"{rid}: Q2 呼叫點 {cid} 不得僅以制式文字排除")
                excluded_reasons.append(str(row.get("reason", "")).strip())
            elif row.get("status") == "verified" and (not isinstance(row.get("binding"), str) or row["binding"] not in BINDINGS):
                issues.append(f"{rid}: Q2 呼叫點 {cid} 未說明實際目標繫結方式")
        # 大量同一句排除敘述代表沒有逐呼叫點核對，不用任意結果比例限制。
        counts = Counter(_reason_template(r) for r in excluded_reasons if r)
        if len(excluded_reasons) >= 8 and counts and counts.most_common(1)[0][1] >= 8:
            issues.append(f"{rid}: Q2 多個呼叫點共用制式化的排除理由，須逐一查證")
    return issues
