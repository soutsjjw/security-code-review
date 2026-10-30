#!/usr/bin/env python3
"""來源快照與規則責任守門：來源盤點雜湊、快照建立／核對、規則檢核範圍與證據閉包。

本模組是單代理守門的下層，不得匯入 review_safety／adversarial_recheck／analysis_prepare。
測試替換本層函式時請 patch 本模組；review_safety 一律以 review_snapshot.<名稱> 取用。
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from review_core import write_json_atomic as _write
from scope_paths import EXCLUDED_DIRS, _default_rule
from source_coverage import SOURCE_FILENAMES, SOURCE_SUFFIXES
from source_reader import source_digest

RELATIVE = Path("reports/security-code-review")
SNAPSHOT = Path("analysis/review-snapshot.json")
CLOSURES = Path("analysis/rule-closures.json")
STAGED = Path("analysis/staged")
RECHECK = Path("analysis/recheck-required.json")
INDEX = Path("analysis/structure-index.json")
CONTROL_VERIFICATIONS = Path("analysis/control-verifications.json")
DECISION_AUDITS = Path("analysis/decision-audits.json")
ADVERSARIAL_REVIEWS = Path("analysis/adversarial-reviews.json")
REVIEW_SCOPES = ("local", "cross_file", "project")


def report_dir(target: Path) -> Path:
    return target.resolve() / RELATIVE


def _read(path: Path, default: Any = None) -> Any:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


def _revision(target: Path) -> str:
    result = subprocess.run(["git", "-C", str(target), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else "not-a-git-repository"


def rule_scopes() -> dict[str, str]:
    """規則檢核範圍以 rules.json 的 inspection.review_scope 為唯一來源。

    project 為全專案責任檢查，即使沒有任何檔案命中也必須執行。
    """
    master = Path(__file__).resolve().parents[2] / "rules.json"
    scopes = {r["id"]: r.get("inspection", {}).get("review_scope")
              for r in json.loads(master.read_text(encoding="utf-8"))["rules"]}
    invalid = sorted(rid for rid, scope in scopes.items() if scope not in REVIEW_SCOPES)
    if invalid:
        raise ValueError(f"規則缺少有效的 inspection.review_scope：{', '.join(invalid)}")
    return dict(sorted(scopes.items()))


def source_files(root: Path, excluded: list[str] | None = None) -> dict[str, str]:
    """和既有來源覆蓋清單共用副檔名與排除原則，雜湊由本機計算。"""
    excluded = excluded or []
    files: dict[str, str] = {}
    for current, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS and not d.startswith(".codegraph-") and not (Path(current) / d).is_symlink()
                  and not _default_rule((Path(current) / d).relative_to(root).as_posix())
                  and not any((Path(current) / d).relative_to(root).as_posix() == p or
                              (Path(current) / d).relative_to(root).as_posix().startswith(p.rstrip("/") + "/")
                              for p in excluded)]
        for name in names:
            path = Path(current) / name
            if not path.is_file() or path.is_symlink():
                continue
            rel = path.relative_to(root).as_posix()
            if _default_rule(rel) or any(rel == p or rel.startswith(p.rstrip("/") + "/") for p in excluded):
                continue
            if path.suffix.lower() in SOURCE_SUFFIXES or name in SOURCE_FILENAMES or path.suffix.lower() == ".vue":
                files[rel] = source_digest(path.read_bytes())
    return dict(sorted(files.items()))


def current_hashes(target: Path, exclusions: list[str]) -> dict[str, str]:
    return source_files(target.resolve(), exclusions)


def initialize_snapshot(target: Path, source_hashes: dict[str, str],
                        exclusions: list[str]) -> None:
    path = report_dir(target) / SNAPSHOT
    original = _read(path)
    proposed = {
        "schema_version": 1,
        "git_revision": _revision(target),
        "source_hashes": source_hashes,
        "excluded_paths": sorted(set(exclusions)),
    }
    if original is None:
        _write(path, proposed)
        return
    if original != proposed:
        raise ValueError("審查快照與目前來源／Git 版本不同；停止沿用舊證據。"
                         "先核對變更、重新檢核受影響規則，再明確執行 snapshot-refresh。")


def snapshot_errors(target: Path) -> list[str]:
    original = _read(report_dir(target) / SNAPSHOT)
    if original is None:
        return []  # 舊審查紀錄沒有新協定，不擅自宣稱其已完成 P0 守門。
    if not isinstance(original, dict) or original.get("schema_version") != 1:
        return ["審查快照版本無效"]
    assessment = _read(report_dir(target) / "assessment.json", {}) or {}
    excluded = sorted({str(item.get("path", "")) for item in
                       (assessment.get("scope_details") or {}).get("excluded_paths", [])
                       if isinstance(item, dict)})
    if excluded != original.get("excluded_paths", []):
        return ["審查排除範圍已改變，須重新盤點與核對來源快照"]
    try:
        actual = current_hashes(target, original.get("excluded_paths", []))
    except (OSError, ValueError, TypeError) as exc:
        return [f"無法核對來源快照：{exc}"]
    before = original.get("source_hashes")
    if not isinstance(before, dict):
        return ["審查快照未記錄完整來源 SHA256"]
    index = _read(report_dir(target) / INDEX, {}) or {}
    if index.get("source_hashes") != before:
        return ["分析結構索引與審查快照不同步；須重新執行 analysis_prepare.py 後才可審查或交付"]
    changed = sorted(k for k in actual.keys() & before.keys() if actual[k] != before[k])
    added = sorted(actual.keys() - before.keys())
    removed = sorted(before.keys() - actual.keys())
    if changed or added or removed:
        return [f"來源快照已異動：修改 {changed[:5]}；新增 {added[:5]}；刪除 {removed[:5]}。"
                "必須重新審查受影響的規則及檔案"]
    if _revision(target) != original.get("git_revision"):
        return ["Git Revision 已改變，但來源 SHA256 均未異動；"
                "須明確執行 snapshot-refresh 更新版本錨點，不得跳過完整性守門"]
    return []


def scope_tasks(target: Path) -> list[dict]:
    """70 項均出現在待辦；缺少來源命中不能當作 N/A。"""
    index = _read(report_dir(target) / INDEX, {}) or {}
    candidates = index.get("rule_candidates") or {}
    relations = index.get("typed_relationships") or []
    closures = _read(report_dir(target) / CLOSURES, {}) or {}
    tasks = []
    for rid, scope in rule_scopes().items():
        paths = sorted(p for p, hits in candidates.items()
                       if any(hit.get("rule_id") == rid for hit in hits))
        edge_ids = [edge["id"] for edge in relations
                    if edge.get("source") in paths or edge.get("target") in paths]
        callsite_ids = sorted({
            call["id"] for origin, entries in (index.get("cross_file_call_hints") or {}).items()
            for call in entries if isinstance(call, dict) and isinstance(call.get("id"), str)
            and (origin in paths or any(
                item.get("path") in paths for item in call.get("possible_targets", [])
                if isinstance(item, dict)
            ))
        })
        tasks.append({"rule_id": rid, "scope": scope,
                      "candidate_paths": paths,
                      "relationship_ids": sorted(set(edge_ids)),
                      "callsite_ids": callsite_ids,
                      "needs_closure": scope != "local" and rid not in closures,
                      "project_responsibility_check": scope == "project"})
    return tasks


def closure_errors(target: Path, assessment: dict, *, index_override: dict | None = None,
                   snapshot_override: dict | None = None,
                   closures_override: dict | None = None,
                   diagnostics: dict[str, dict] | None = None,
                   verifications_override: dict | None = None,
                   audits_override: dict | None = None) -> list[str]:
    """明確記錄人工查證的邊界及全專案責任；不以索引候選冒充結論。"""
    if snapshot_override is None and not (report_dir(target) / SNAPSHOT).exists():
        return []
    closures = closures_override if closures_override is not None else (_read(report_dir(target) / CLOSURES, {}) or {})
    scopes = rule_scopes()
    index = index_override if index_override is not None else (_read(report_dir(target) / INDEX, {}) or {})
    edges = index.get("typed_relationships", [])
    known_edges = {r["id"] for r in edges}
    candidates = index.get("rule_candidates") or {}
    snapshot = snapshot_override if snapshot_override is not None else (_read(report_dir(target) / SNAPSHOT, {}) or {})
    current = set(snapshot.get("source_hashes", {}))
    errors = []
    from cross_file_evidence import trace_errors
    q2 = index.get("cross_file_evidence_version") == 1
    for check in assessment.get("checks", []):
        rid = check.get("id")
        if rid not in scopes or (check.get("execution") or {}).get("state") != "completed":
            continue
        if scopes[rid] == "local":
            continue
        closure = closures.get(rid)
        if not isinstance(closure, dict):
            errors.append(f"{rid}: 缺少 {scopes[rid]} 規則整合／控制責任結案紀錄")
            continue
        if closure.get("status") != check.get("status"):
            errors.append(f"{rid}: 結案狀態與正式規則判定衝突")
        if not isinstance(closure.get("summary"), str) or len(closure["summary"].strip()) < 20:
            errors.append(f"{rid}: 缺少跨檔／全專案控制鏈結案說明")
        paths = closure.get("examined_paths")
        if not isinstance(paths, list) or any(p not in current for p in paths):
            errors.append(f"{rid}: 結案查核路徑未列於當前來源快照")
        if not isinstance(closure.get("control_owner"), str) or len(closure["control_owner"].strip()) < 5:
            errors.append(f"{rid}: 未說明控制責任元件或外部責任歸屬")
        if not isinstance(closure.get("search_summary"), str) or len(closure["search_summary"].strip()) < 20:
            errors.append(f"{rid}: 缺少控制缺席／全域搜尋的實際範圍與結果")
        ids = closure.get("examined_relationship_ids")
        if not isinstance(ids, list) or any(x not in known_edges for x in ids):
            errors.append(f"{rid}: 跨檔關聯 ID 無效，須由索引與來源逐項核對")
            ids = []
        dismissed = closure.get("dismissed_relationships", {})
        if not isinstance(dismissed, dict) or any(
                x not in known_edges or (
                    not isinstance(note, dict) if q2 else
                    (not isinstance(note, str) or len(note.strip()) < 20)
                )
                for x, note in dismissed.items()):
            errors.append(f"{rid}: 被排除的關聯須使用有效 ID 與至少 20 字具體排除理由")
            dismissed = {}
        candidate_paths = {p for p, hits in candidates.items()
                           if any(hit.get("rule_id") == rid for hit in hits)}
        # 新版依據明確控制鏈錨點縮小關聯候選，不因 examined_paths
        # 記錄了全專案清單而將所有呼叫點與關聯重複掛到每一條規則。
        trace = closure.get("control_trace")
        anchors = {n.get("path") for n in trace.get("nodes", [])
                   if isinstance(n, dict) and isinstance(n.get("path"), str)} \
            if q2 and isinstance(trace, dict) and isinstance(trace.get("nodes"), list) else set()
        relevant_paths = candidate_paths | (anchors if q2 else
                                             (set(paths) if isinstance(paths, list) else set()))
        related = {edge["id"] for edge in edges
                   if edge.get("source") in relevant_paths or edge.get("target") in relevant_paths}
        unresolved = sorted(related - set(ids) - set(dismissed))
        if unresolved:
            if diagnostics is not None:
                diagnostics[rid] = {
                    "count": len(unresolved),
                    "relationship_ids": unresolved,
                }
            errors.append(f"{rid}: 尚有 {len(unresolved)} 筆跨檔／組態候選未查證或排除："
                          + "、".join(unresolved[:5]))
        # P1 只對新索引中與本規則相關的呼叫點加上明確覆核要求。
        # Symbol / name-based 邊都只是候選，不能自動宣稱 verified。
        if index.get("schema_version", 0) >= 3:
            callsites = {
                call["id"]: (origin, call)
                for origin, entries in (index.get("cross_file_call_hints") or {}).items()
                for call in entries if isinstance(call, dict) and isinstance(call.get("id"), str)
                and (origin in relevant_paths or any(
                    isinstance(target, dict) and target.get("path") in relevant_paths
                    for target in call.get("possible_targets", [])
                ))
            }
            reviews = closure.get("callsite_reviews", {})
            missing_callsites = {cid: origin for cid, (origin, _) in callsites.items()
                                 if not isinstance(reviews, dict)
                                 or not isinstance(reviews.get(cid), dict)}
            if diagnostics is not None and missing_callsites:
                diag = diagnostics.setdefault(rid, {"count": 0, "relationship_ids": []})
                by_source: dict[str, list[str]] = {}
                for cid, origin in sorted(missing_callsites.items()):
                    by_source.setdefault(origin, []).append(cid)
                diag["unverified_callsite_count"] = len(missing_callsites)
                diag["unverified_callsites_by_source"] = by_source
            if not isinstance(reviews, dict):
                errors.append(f"{rid}: callsite_reviews 必須為呼叫點 ID 對應的覆核紀錄")
                reviews = {}
            unknown = set(reviews) - set(callsites)
            if unknown:
                errors.append(f"{rid}: 包含不屬於本規則責任範圍的呼叫點："
                              + "、".join(sorted(unknown)[:5]))
            for callsite_id, (origin, call) in callsites.items():
                review = reviews.get(callsite_id)
                if not isinstance(review, dict):
                    errors.append(f"{rid}: 跨檔呼叫點 {callsite_id} 尚未由 Agent 核對來源")
                    continue
                status = review.get("status")
                reason = review.get("reason", "")
                if status not in {"verified", "excluded"} or not isinstance(reason, str) or len(reason.strip()) < 20:
                    errors.append(f"{rid}: 呼叫點 {callsite_id} 須提供具體 verified/excluded 判定與理由")
                    continue
                if origin not in paths:
                    errors.append(f"{rid}: 呼叫點 {callsite_id} 來源未列入 examined_paths")
                selected = review.get("selected_targets", [])
                candidate_targets = {item.get("path") for item in call.get("possible_targets", [])
                                     if isinstance(item, dict)}
                if not isinstance(selected, list) or any(
                    not isinstance(p, str) or p not in candidate_targets for p in selected
                ):
                    errors.append(f"{rid}: 呼叫點 {callsite_id} 目標必須來自已列出的候選來源")
                elif status == "verified" and (
                    not selected or any(p not in paths for p in selected)
                ):
                    errors.append(f"{rid}: 呼叫點 {callsite_id} 已確認目標必須列入 examined_paths")
                elif status == "excluded" and selected:
                    errors.append(f"{rid}: 呼叫點 {callsite_id} 已排除，不可同時宣稱確認目標")
        if not isinstance(closure.get("open_issues"), list):
            errors.append(f"{rid}: open_issues 必須列出尚待補查任務（無則為空陣列）")
        elif closure["open_issues"]:
            errors.append(f"{rid}: 仍有未關閉的跨檔／全專案補查任務")
        if q2:
            errors.extend(trace_errors(
                target, index, snapshot, check, closure, scopes[rid],
                verifications_override=verifications_override,
                audits_override=audits_override,
            ))
        if scopes[rid] == "cross_file" and isinstance(paths, list) and len(paths) == 1:
            # 合法的單檔實作仍可結案，但需說明如何排除其他呼叫端／設定。
            note = closure.get("single_file_justification")
            if not isinstance(note, str) or len(note.strip()) < 20:
                errors.append(f"{rid}: 僅核對單檔，須解釋已如何排除其他必要呼叫鏈")
    return errors
