#!/usr/bin/env python3
"""修復 Wave checkpoint 的狀態讀寫、正式證據指紋與單一寫入者鎖；供協調器、取消與生命週期共用。

本模組不得匯入 review_repair_waves／review_waves_abort／review_waves_lifecycle。
測試替換狀態函式時請 patch 本模組，各呼叫端一律以 review_waves_state.<名稱> 取用。
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
from typing import Any

from review_core import file_sha256 as _file_sha, REPORT_ROOT, write_json_exclusive
from evidence_integrity import MANIFEST, TRACKED
from first_pass_repair import repair_plan
from review_snapshot import STAGED
from review_waves_contracts import verify_sample_chain

REPORT = REPORT_ROOT
STATE = REPORT / "logs/repair-waves/state.json"
VERSION = 2


def _read(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path.name}: 必須是 JSON 物件")
    return data


def _assessment(target: Path) -> dict[str, Any]:
    return _read(target / REPORT / "assessment.json")


def _evidence_state(target: Path) -> dict[str, Any]:
    from review_snapshot import snapshot_errors
    from evidence_integrity import errors as integrity_errors
    failures = snapshot_errors(target) + integrity_errors(target)
    if failures:
        raise ValueError("正式來源／完整性守門未通過：" + "；".join(failures[:8]))
    assessment = target / REPORT / "assessment.json"
    from review_snapshot import SNAPSHOT as FORMAL_SNAPSHOT
    snap_path = target / REPORT / FORMAL_SNAPSHOT
    if not assessment.is_file() or not snap_path.is_file():
        raise ValueError("缺少正式 assessment 或來源快照")
    manifest = target / MANIFEST
    # The integrity validator above is authoritative. These raw hashes serve
    # only to invalidate stale operational checkpoints after legitimate writes.
    tracked = {relative: (_file_sha(target / REPORT / relative)
                          if (target / REPORT / relative).is_file() else None)
               for relative in TRACKED}
    return {"assessment_sha256": _file_sha(assessment),
            "source_snapshot_sha256": _file_sha(snap_path),
            "tracked_sha256": tracked,
            "manifest_sha256": _file_sha(manifest) if manifest.is_file() else None}


def _rule_ids_from_file(row: dict) -> set[str]:
    """Collect owners without assigning rules from generic path heuristics."""
    owners = {rr.get("rule_id") for rr in row.get("rule_reviews", [])
              if isinstance(rr, dict) and isinstance(rr.get("rule_id"), str)}
    screening = row.get("category_screening")
    if isinstance(screening, list):
        for item in screening:
            if isinstance(item, dict):
                owners.update(r for r in item.get("rule_ids", [])
                              if isinstance(r, str))
    elif isinstance(screening, dict):
        for item in screening.values():
            if isinstance(item, dict):
                owners.update(r for r in item.get("rule_ids", [])
                              if isinstance(r, str))
    return owners


def _formal_fingerprints(target: Path) -> dict[str, Any]:
    """Digests of real formal records; checkpoint is not itself formal proof."""
    assessment = _assessment(target)
    analysis = target / REPORT / "analysis"
    snapshots: dict[str, Any] = {}
    for section, filename in (("closures", "rule-closures.json"),
                              ("control_verifications", "control-verifications.json"),
                              ("decision_audits", "decision-audits.json")):
        file = analysis / filename
        rows = _read(file) if file.is_file() else {}
        if not isinstance(rows, dict):
            raise ValueError(f"{filename} 必須是物件")
        snapshots[section] = {rid: _digest(item) for rid, item in rows.items()}
    checks = assessment.get("checks") or []
    files = assessment.get("file_reviews") or []
    findings = assessment.get("findings") or []
    if not all(isinstance(x, dict) for x in checks + files + findings):
        raise ValueError("正式 assessment 紀錄格式錯誤")
    snapshots["checks"] = {c["id"]: {"digest": _digest(c), "status": c.get("status")}
                           for c in checks}
    snapshots["file_reviews"] = {f["path"]: {"digest": _digest(f),
                                             "owners": sorted(_rule_ids_from_file(f))}
                                  for f in files}
    snapshots["findings"] = {f["id"]: {"digest": _digest(f),
                                       "owners": sorted(set(f.get("check_ids") or []))}
                              for f in findings}
    # Capture second-pass-only formal commits as well. Without these hashes,
    # an interrupted adversarial-review transaction appears to have no effect.
    for key, filename in (("adversarial_reviews", "adversarial-reviews.json"),
                          ("first_pass_baseline", "first-pass-baseline.json")):
        path = analysis / filename
        snapshots[key] = _file_sha(path) if path.is_file() else None
    return snapshots


def _formal_diff(previous: dict, current: dict) -> tuple[set[str], set[str]]:
    """Conservatively include externally changed evidence in sampling."""
    changed: set[str] = set()
    mandatory: set[str] = set()
    all_rules = set(previous["checks"]) | set(current["checks"])
    for section in ("checks", "closures", "control_verifications", "decision_audits"):
        old, new = previous[section], current[section]
        for rid in set(old) | set(new):
            if old.get(rid) == new.get(rid):
                continue
            changed.add(rid)
            if section in {"closures", "decision_audits", "control_verifications"}:
                mandatory.add(rid)
            if section == "checks":
                a = (old.get(rid) or {}).get("status")
                b = (new.get(rid) or {}).get("status")
                if a != b and "fail" in (a, b):
                    mandatory.add(rid)
    for section in ("file_reviews", "findings"):
        old, new = previous[section], current[section]
        for key in set(old) | set(new):
            if old.get(key) == new.get(key):
                continue
            owners = set((old.get(key) or {}).get("owners") or []) | set(
                (new.get(key) or {}).get("owners") or [])
            if not owners:
                owners = all_rules  # unknown scope must not silently disappear
            changed.update(owners)
            if section == "findings":
                mandatory.update(owners)
    return changed, mandatory


def _stage_clean(target: Path) -> None:
    directory = target / REPORT / STAGED
    if directory.is_dir() and list(directory.glob("*.json")):
        raise ValueError("存在其他待整合暫存資料；先合法處理，不得混入本批")


def _diagnose_and_plan(target: Path) -> tuple[dict, dict]:
    from review_blockers import diagnose
    assessment = _assessment(target)
    diagnosis = diagnose(target, assessment)
    plan = repair_plan(assessment, diagnosis)
    return diagnosis, plan


def _write_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError("不接受指向外部的 checkpoint 符號連結")
    temp = path.with_name(path.name + ".pending")
    if temp.exists() or temp.is_symlink():
        raise ValueError("發現未完成的 checkpoint 暫存；需先人工排除")
    write_json_exclusive(temp, state, sort_keys=True)
    os.replace(temp, path)


@contextmanager
def _single_writer(target: Path):
    lock = target / STATE.parent / ".writer.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ValueError("已有修復協調器正在寫入，或舊鎖尚未人工調查") from exc
    try:
        os.close(fd)
        yield
    finally:
        lock.unlink(missing_ok=True)


def _load_state(target: Path) -> dict:
    path = target / STATE
    if path.is_symlink():
        raise ValueError("不接受 checkpoint 符號連結")
    state = _read(path)
    if state.get("schema_version") != VERSION or not isinstance(state.get("batches"), list):
        raise ValueError("不認得的修復 checkpoint 版本")
    return state


def _assert_state_current(target: Path, state: dict) -> None:
    if state.get("inflight"):
        raise ValueError("存在待對帳的正式交易；禁止重放，先執行 --reconcile")
    if state.get("sample_chain") is not None:
        verify_sample_chain(state["sample_chain"])
    current = _evidence_state(target)
    if current != state.get("last_evidence"):
        raise ValueError("正式資料或來源快照已在協調器外變更；停止並人工核對")


def _all_completed(state: dict) -> bool:
    return len(state["completed_batches"]) == len(state["batches"])


def _next_batch(state: dict) -> dict | None:
    done = set(state["completed_batches"])
    for batch in state["batches"]:
        if batch["batch_id"] not in done and set(batch["depends_on_batch_ids"]) <= done:
            return batch
    return None


def _batch_blockers(batch: dict, tasks: list[dict]) -> set[tuple[str, tuple[str, ...]]]:
    ids = set(batch["task_ids"])
    return {(item["message"], tuple(sorted(item["rule_ids"])))
            for task in tasks if task["task_id"] in ids
            for item in task["blocker_details"]}


def _blocker_keys(diagnostic: dict) -> set[tuple[str, tuple[str, ...]]]:
    return {(str(b["message"]), tuple(sorted(b.get("rule_ids") or [])))
            for b in diagnostic.get("blockers", [])}
