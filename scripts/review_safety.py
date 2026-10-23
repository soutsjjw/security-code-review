#!/usr/bin/env python3
"""單代理審查的六項 P0 守門：來源快照、規則責任、證據閉包、暫存及衝突整合。

僅處理審查資料，絕不自動作安全判定，也不建立或啟動子代理。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

RELATIVE = Path("reports/security-code-review")
SNAPSHOT = Path("analysis/review-snapshot.json")
CLOSURES = Path("analysis/rule-closures.json")
STAGED = Path("analysis/staged")
RECHECK = Path("analysis/recheck-required.json")
INDEX = Path("analysis/structure-index.json")
CONTROL_VERIFICATIONS = Path("analysis/control-verifications.json")
DECISION_AUDITS = Path("analysis/decision-audits.json")

# 全專案責任檢查即使沒有任何檔案命中也必須執行。
PROJECT_RULES = frozenset((
    "AC-03 AC-05 AC-07 AU-04 CR-01 CR-03 CR-05 EH-04 EH-05 EH-06 "
    "LG-03 LG-04 LG-05 LG-06 LG-07 LG-09 DP-01 DP-02 DP-03 DP-04 "
    "PD-01 PD-08 BC-01 BC-02 BC-03 BC-04 BC-05 BC-06 BC-07 SI-01 SI-02"
).split())
CROSS_FILE_RULES = frozenset((
    "AC-01 AC-02 AC-04 AC-06 AC-08 AU-01 AU-02 AU-03 AU-05 AU-06 "
    "AU-07 AU-08 AU-09 AU-10 IN-01 IN-02 IN-03 IN-04 IN-05 IN-06 "
    "IN-07 IN-08 CR-02 CR-04 CR-06 EH-01 EH-02 LG-01 LG-02 LG-08 "
    "LG-10 PD-02 PD-03 PD-04 PD-05 PD-06 PD-07 SI-03"
).split())


def report_dir(target: Path) -> Path:
    return target.resolve() / RELATIVE


def _read(path: Path, default: Any = None) -> Any:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


def _write(path: Path, value: Any) -> None:
    """僅以同目錄 replace 原子替換單一檔案，避免中途留下截斷 JSON。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp.replace(path)


def _revision(target: Path) -> str:
    result = subprocess.run(["git", "-C", str(target), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else "not-a-git-repository"


def rule_scopes() -> dict[str, str]:
    master = Path(__file__).resolve().parents[1] / "rules.json"
    ids = {r["id"] for r in json.loads(master.read_text(encoding="utf-8"))["rules"]}
    if PROJECT_RULES & CROSS_FILE_RULES or (PROJECT_RULES | CROSS_FILE_RULES) - ids:
        raise ValueError("規則檢核範圍定義重複或包含未知 ID")
    return {rid: ("project" if rid in PROJECT_RULES else
                  "cross_file" if rid in CROSS_FILE_RULES else "local")
            for rid in sorted(ids)}


def current_hashes(target: Path, exclusions: list[str]) -> dict[str, str]:
    # 使用原有來源盤點與標準化 SHA256，避免第二套覆蓋率定義。
    from analysis_prepare import source_files
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
    if _revision(target) != original.get("git_revision"):
        return ["Git Revision 已改變，禁止混用不同提交的審查證據"]
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


def closure_errors(target: Path, assessment: dict) -> list[str]:
    """明確記錄人工查證的邊界及全專案責任；不以索引候選冒充結論。"""
    if not (report_dir(target) / SNAPSHOT).exists():
        return []
    closures = _read(report_dir(target) / CLOSURES, {}) or {}
    scopes = rule_scopes()
    index = _read(report_dir(target) / INDEX, {}) or {}
    edges = index.get("typed_relationships", [])
    known_edges = {r["id"] for r in edges}
    candidates = index.get("rule_candidates") or {}
    current = set((_read(report_dir(target) / SNAPSHOT, {}) or {}).get("source_hashes", {}))
    errors = []
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
                x not in known_edges or not isinstance(note, str) or len(note.strip()) < 20
                for x, note in dismissed.items()):
            errors.append(f"{rid}: 被排除的關聯須使用有效 ID 與至少 20 字具體排除理由")
            dismissed = {}
        candidate_paths = {p for p, hits in candidates.items()
                           if any(hit.get("rule_id") == rid for hit in hits)}
        relevant_paths = candidate_paths | (set(paths) if isinstance(paths, list) else set())
        related = {edge["id"] for edge in edges
                   if edge.get("source") in relevant_paths or edge.get("target") in relevant_paths}
        unresolved = sorted(related - set(ids) - set(dismissed))
        if unresolved:
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
                candidates = {item.get("path") for item in call.get("possible_targets", [])
                              if isinstance(item, dict)}
                if not isinstance(selected, list) or any(
                    not isinstance(p, str) or p not in candidates for p in selected
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
        if scopes[rid] == "cross_file" and isinstance(paths, list) and len(paths) == 1:
            # 合法的單檔實作仍可結案，但需說明如何排除其他呼叫端／設定。
            note = closure.get("single_file_justification")
            if not isinstance(note, str) or len(note.strip()) < 20:
                errors.append(f"{rid}: 僅核對單檔，須解釋已如何排除其他必要呼叫鏈")
    return errors


def safety_errors(target: Path, assessment: dict) -> list[str]:
    from control_effectiveness import verification_errors
    from decision_adjudication import adjudication_errors
    errors = (snapshot_errors(target) + closure_errors(target, assessment)
              + verification_errors(target, assessment.get("checks", []))
              + adjudication_errors(target, assessment.get("checks", [])))
    outstanding = _read(report_dir(target) / RECHECK, {}) or {}
    ids = outstanding.get("rule_ids", [])
    if ids:
        errors.append("來源異動後仍有待重新檢核的規則：" + "、".join(ids[:15]))
    return errors


def _fingerprint(finding: dict) -> str:
    evidence = finding.get("evidence") or []
    locations = sorted((str(e.get("path") or ""), e.get("line_start") or 0,
                        e.get("line_end") or 0) for e in evidence if isinstance(e, dict))
    basis = json.dumps([finding.get("title", "").strip().casefold(),
                        sorted(finding.get("check_ids", [])), locations],
                       sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def stage(target: Path, payload_path: Path) -> str:
    failures = snapshot_errors(target)
    if failures:
        raise ValueError("；".join(failures))
    if not (report_dir(target) / SNAPSHOT).exists():
        raise ValueError("請先執行 analysis_prepare.py 建立來源快照")
    payload = _read(payload_path)
    if not isinstance(payload, dict):
        raise ValueError("暫存資料必須為 JSON 物件")
    for key in ("file_reviews", "checks", "findings", "closures", "control_verifications", "decision_audits"):
        is_map = key in {"closures", "control_verifications", "decision_audits"}
        value = payload.get(key, {} if is_map else [])
        if not isinstance(value, dict if is_map else list):
            raise ValueError(f"暫存 {key} 型別錯誤")
    snapshot = _read(report_dir(target) / SNAPSHOT)
    staged = {"snapshot_git_revision": snapshot["git_revision"],
              "source_hashes": snapshot["source_hashes"],
              "payload": payload}
    raw = json.dumps(staged, sort_keys=True, ensure_ascii=False)
    key = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]
    path = report_dir(target) / STAGED / f"{key}.json"
    _write(path, staged)
    return path.as_posix()


def integrate(target: Path, *, allow_revision: bool = False) -> dict:
    failures = snapshot_errors(target)
    if failures:
        raise ValueError("；".join(failures))
    folder = report_dir(target) / STAGED
    paths = sorted(folder.glob("*.json")) if folder.exists() else []
    if not paths:
        return {"applied": 0, "message": "沒有待整合的暫存資料"}
    assessment_path = report_dir(target) / "assessment.json"
    data = _read(assessment_path)
    if not isinstance(data, dict):
        raise ValueError("assessment.json 不存在或格式錯誤")
    snapshot = _read(report_dir(target) / SNAPSHOT)
    files = {r["path"]: r for r in data.get("file_reviews", [])}
    checks = {r["id"]: r for r in data.get("checks", [])}
    findings = {r["id"]: r for r in data.get("findings", [])}
    closures = _read(report_dir(target) / CLOSURES, {}) or {}
    control_verifications = _read(report_dir(target) / CONTROL_VERIFICATIONS, {}) or {}
    decision_audits = _read(report_dir(target) / DECISION_AUDITS, {}) or {}
    known_fingerprints = {_fingerprint(f): fid for fid, f in findings.items()}
    new_files: set[str] = set()
    new_checks: set[str] = set()
    new_closures: set[str] = set()
    new_control_verifications: set[str] = set()
    new_decision_audits: set[str] = set()
    aliases: dict[str, str] = {}
    recheck = _read(report_dir(target) / RECHECK, {}) or {}
    required_recheck = set(recheck.get("rule_ids", []))
    newly_rechecked: set[str] = set()

    # 先於記憶體完整調和、偵測衝突，絕不分批覆蓋正式檔。
    for path in paths:
        staged = _read(path)
        if (staged.get("snapshot_git_revision") != snapshot["git_revision"]
                or staged.get("source_hashes") != snapshot["source_hashes"]):
            raise ValueError(f"{path.name}: 暫存使用不同的來源快照")
        part = staged["payload"]
        for record in part.get("file_reviews", []):
            name = record["path"]
            if name not in snapshot["source_hashes"]:
                raise ValueError(f"{name}: 暫存檔不在來源快照")
            if name in files and files[name] != record:
                if name in new_files or not allow_revision:
                    raise ValueError(f"{name}: 逐檔結果衝突，須人工核對後才允許修訂")
            files[name] = record
            new_files.add(name)
        for record in part.get("findings", []):
            fid = record["id"]
            fingerprint = _fingerprint(record)
            if fid in findings and findings[fid] != record:
                raise ValueError(f"{fid}: Finding ID 衝突，拒絕覆寫既有弱點")
            if fingerprint in known_fingerprints and known_fingerprints[fingerprint] != fid:
                canonical = findings[known_fingerprints[fingerprint]]
                # 同位置／標題不代表證據、影響與建議相同；不得靜默遺失詳情。
                if ({k: v for k, v in canonical.items() if k != "id"} !=
                        {k: v for k, v in record.items() if k != "id"}):
                    raise ValueError(f"{fid}: Finding 疑似重複但內容不同，須人工整併證據")
                aliases[fid] = known_fingerprints[fingerprint]
                continue
            findings[fid] = record
            known_fingerprints[fingerprint] = fid
        for record in part.get("checks", []):
            rid = record["id"]
            if rid not in checks:
                raise ValueError(f"{rid}: 不存在的 70 項檢核 ID")
            record = dict(record)
            if "finding_ids" in record:
                record["finding_ids"] = sorted(set(aliases.get(x, x) for x in record["finding_ids"]))
            if rid in new_checks and checks[rid] != record:
                raise ValueError(f"{rid}: 多份暫存規則結果衝突，需人工裁決")
            if checks[rid] != record and (checks[rid].get("execution") or {}).get("state") == "completed":
                if checks[rid].get("status") == "fail" and record.get("status") != "fail":
                    raise ValueError(f"{rid}: 不允許未裁決即將已確認弱點改判為非 fail")
                if not allow_revision:
                    raise ValueError(f"{rid}: 已完成的規則不同，須明確人工允許修訂")
            checks[rid] = record
            new_checks.add(rid)
            if rid in required_recheck and (record.get("execution") or {}).get("state") == "completed":
                if not record.get("evidence") or not (record.get("execution") or {}).get("methods"):
                    raise ValueError(f"{rid}: 來源異動後重新完成須附實際分析證據及方法")
                newly_rechecked.add(rid)
        for rid, record in part.get("closures", {}).items():
            if rid not in rule_scopes():
                raise ValueError(f"{rid}: 結案包含未知規則")
            if rid in closures and closures[rid] != record and (rid in new_closures or not allow_revision):
                raise ValueError(f"{rid}: 跨檔結案紀錄衝突，須人工核對")
            closures[rid] = record
            new_closures.add(rid)
        for rid, record in part.get("control_verifications", {}).items():
            if rid not in checks:
                raise ValueError(f"{rid}: P2 控制有效性包含未知規則")
            if not isinstance(record, dict):
                raise ValueError(f"{rid}: P2 控制有效性紀錄必須為物件")
            if (rid in control_verifications and control_verifications[rid] != record
                    and (rid in new_control_verifications or not allow_revision)):
                raise ValueError(f"{rid}: P2 控制有效性紀錄衝突，須人工核對或明確允許修訂")
            control_verifications[rid] = record
            new_control_verifications.add(rid)
        for rid, record in part.get("decision_audits", {}).items():
            if rid not in checks:
                raise ValueError(f"{rid}: P3 判定紀錄包含未知規則")
            if not isinstance(record, dict):
                raise ValueError(f"{rid}: P3 判定紀錄必須為物件")
            if (rid in decision_audits and decision_audits[rid] != record
                    and (rid in new_decision_audits or not allow_revision)):
                raise ValueError(f"{rid}: P3 判定紀錄衝突，須人工核對或明確允許修訂")
            decision_audits[rid] = record
            new_decision_audits.add(rid)

    # 不允許因去重而留下錯誤 Finding ID 參照。
    for check in checks.values():
        for fid in check.get("finding_ids", []):
            if fid not in findings:
                raise ValueError(f"{check['id']}: 找不到 Finding {fid}")
    for record in findings.values():
        for rid in record.get("check_ids", []):
            if rid not in checks:
                raise ValueError(f"Finding 關聯未知規則 {rid}")
    data["file_reviews"] = [files[p] for p in sorted(files)]
    data["checks"] = [checks[r["id"]] for r in data["checks"]]
    data["findings"] = [findings[p] for p in sorted(findings)]
    # 正式驗證必須在完整審查完成後執行；partial 仍可保留 pending。
    _write(report_dir(target) / CLOSURES, closures)
    _write(report_dir(target) / CONTROL_VERIFICATIONS, control_verifications)
    _write(report_dir(target) / DECISION_AUDITS, decision_audits)
    _write(assessment_path, data)
    if required_recheck:
        recheck["rule_ids"] = sorted(required_recheck - newly_rechecked)
        _write(report_dir(target) / RECHECK, recheck)
    for path in paths:
        path.unlink()
    return {"applied": len(paths), "files": len(new_files),
            "checks": len(new_checks), "findings": len(findings), "closures": len(new_closures),
            "control_verifications": len(new_control_verifications),
            "decision_audits": len(new_decision_audits)}


def refresh_snapshot(target: Path) -> None:
    folder = report_dir(target) / STAGED
    if folder.is_dir() and any(folder.glob("*.json")):
        raise ValueError("尚有未整合暫存；禁止刷新來源快照")
    old = _read(report_dir(target) / SNAPSHOT)
    if old is None:
        raise ValueError("尚未建立審查快照")
    assessment = _read(report_dir(target) / "assessment.json", {}) or {}
    excludes = sorted({str(row.get("path", "")) for row in
                       (assessment.get("scope_details") or {}).get("excluded_paths", [])
                       if isinstance(row, dict)})
    current = current_hashes(target, excludes)
    _write(report_dir(target) / SNAPSHOT,
           {"schema_version": 1, "git_revision": _revision(target),
            "source_hashes": current, "excluded_paths": excludes})
    # 原有結論、Findings 和 file_reviews 保留以供追溯，不自動宣稱符合。
    # 失去可驗證依賴閉包時，保守要求所有 completed 規則重新查證。
    assessment = _read(report_dir(target) / "assessment.json", {}) or {}
    completed = [row["id"] for row in assessment.get("checks", [])
                 if (row.get("execution") or {}).get("state") == "completed"]
    _write(report_dir(target) / RECHECK,
           {"rule_ids": sorted(completed), "reason": "審查來源或 Git 版本已變更，需重新驗證影響閉包"})
    (report_dir(target) / CLOSURES).unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="單代理審查完整性守門；不修改受測原始碼")
    parser.add_argument("--target", type=Path, default=Path.cwd())
    parser.add_argument("--plan", action="store_true")
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--stage", type=Path, help="暫存單檔或單批審查 JSON，不能直接寫正式結果")
    parser.add_argument("--integrate", action="store_true")
    parser.add_argument("--allow-revision", action="store_true",
                        help="人工核對後允許覆核既有 completed；仍禁止抹除已確認 fail")
    parser.add_argument("--snapshot-refresh", action="store_true",
                        help="明確更新來源版本，清除過期結案；所有受影響規則須重審")
    args = parser.parse_args()
    try:
        if args.snapshot_refresh:
            refresh_snapshot(args.target)
            print("PASS: snapshot refreshed; previous conclusions require recheck")
        elif args.stage:
            print("STAGED:", stage(args.target, args.stage))
        elif args.integrate:
            print(json.dumps(integrate(args.target, allow_revision=args.allow_revision), ensure_ascii=False))
        elif args.plan:
            print(json.dumps(scope_tasks(args.target), ensure_ascii=False, indent=2))
        elif args.validate:
            errors = safety_errors(args.target, _read(report_dir(args.target) / "assessment.json", {}) or {})
            for error in errors:
                print("ERROR:", error, file=sys.stderr)
            if errors:
                return 1
            print("PASS: review safeguards verified")
        else:
            parser.error("請指定 --plan、--validate、--stage、--integrate 或 --snapshot-refresh")
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
