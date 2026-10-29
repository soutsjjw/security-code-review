#!/usr/bin/env python3
"""Fail-closed cancellation of ONE uncommitted Wave 2 staged transaction.

This operation only quarantines an already-existing staged candidate after
proving that the official Manifest, Journal and tracked evidence have not
changed. It does not replay, apply, rewrite or delete any official evidence.
Quarantine metadata is operational, NOT a signed Journal record.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Any

QUARANTINE = Path("reports/security-code-review/logs/repair-waves/aborted")
RECEIPT_VERSION = 1


def _canonical_sha(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":")).encode("utf-8")).hexdigest()


def _write_new(path: Path, value: dict) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError("隔離稽核紀錄已存在，禁止覆寫")
    with path.open("xb") as out:
        out.write((json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)
                   + "\n").encode("utf-8"))
        out.flush()
        os.fsync(out.fileno())


def _read_record(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError("隔離紀錄不存在或包含符號連結")
    record = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(record, dict):
        raise ValueError("隔離紀錄格式無效")
    return record


def _safe_folder(root: Path) -> Path:
    base = root / QUARANTINE
    # Reject symlinks in every existing component, not only at the leaf.
    for folder in (root / "reports", root / "reports/security-code-review",
                   root / "reports/security-code-review/logs",
                   root / "reports/security-code-review/logs/repair-waves", base):
        if folder.is_symlink():
            raise ValueError("隔離目錄包含 symbolic link")
    base.mkdir(parents=True, exist_ok=True)
    return base


def _verify_official_unchanged(target: Path, state: dict, intent: dict) -> tuple[dict, dict]:
    from review_repair_waves import _evidence_state, _formal_fingerprints
    from evidence_integrity import MANIFEST, PENDING
    if (target / PENDING).exists() or (target / PENDING).is_symlink():
        raise ValueError("存在完整性待提交交易，禁止取消；先處理正式復原")
    evidence = _evidence_state(target)  # checks Journal chain and ALL tracked hashes
    old = intent.get("prior_evidence")
    if (not isinstance(old, dict) or evidence != old
            or evidence != state.get("last_evidence")):
        raise ValueError("正式 Manifest／Journal／追蹤工件與交易前版本不同，禁止取消")
    manifest = _read_record(target / MANIFEST)
    if (not isinstance(manifest.get("head"), str)
            or type(manifest.get("sequence")) is not int or manifest["sequence"] < 0):
        raise ValueError("Manifest sequence/head 格式不合法")
    fingerprints = _formal_fingerprints(target)
    if (fingerprints != intent.get("prior_fingerprints")
            or fingerprints != state.get("formal_fingerprints")):
        raise ValueError("正式逐條證據已變更，禁止取消")
    return manifest, evidence


def _check_original(target: Path, state: dict, intent: dict, batch_id: str) -> None:
    from review_repair_waves import _next_batch
    if (state.get("phase") != "first_pass" or intent.get("phase") != "first_pass"
            or intent.get("batch_id") != batch_id
            or not isinstance(intent.get("payload_sha256"), str)
            or len(intent["payload_sha256"]) != 64):
        raise ValueError("僅允許取消明確指定的第一輪未提交 Wave 2 批次")
    expected = _next_batch(state)
    if not expected or expected.get("batch_id") != batch_id:
        raise ValueError("取消批次已結案、依賴不符或不是目前執行批次")


def _validate_staged(target: Path, state: dict, intent: dict,
                     staged: Path, payload_path: Path | None, manifest: dict) -> dict:
    from review_repair_waves import REPORT, _read, _file_sha, _digest
    from review_safety import STAGED, SNAPSHOT
    source = target / REPORT / STAGED
    if source.is_symlink() or staged.is_symlink() or not staged.is_file():
        raise ValueError("staged 不是可信的一般檔案")
    if staged.parent.resolve() != source.resolve() or staged.suffix != ".json":
        raise ValueError("staged 檔案不在正式暫存目錄")
    record = _read(staged)
    if set(record) != {"snapshot_git_revision", "source_hashes", "payload", "integrity_head"}:
        raise ValueError("staged 欄位異常，不得取消")
    serialized = json.dumps(record, ensure_ascii=False, sort_keys=True)
    expected_name = hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:24] + ".json"
    if staged.name != expected_name:
        raise ValueError("staged 檔名與正式 Stage 內容指紋不一致")
    snapshot = _read(target / REPORT / SNAPSHOT)
    if (record["snapshot_git_revision"] != snapshot.get("git_revision")
            or record["source_hashes"] != snapshot.get("source_hashes")
            or record["integrity_head"] != manifest["head"]):
        raise ValueError("staged 的來源快照或 Manifest head 不一致")
    expected_semantic = intent.get("payload_digest")
    if expected_semantic is not None and expected_semantic != _digest(record["payload"]):
        raise ValueError("staged payload 與 inflight 內容指紋不一致")
    if payload_path is None and expected_semantic is None:
        raise ValueError("舊版 inflight 必須提供原始 --payload 以核對 SHA256")
    if payload_path is not None:
        if (payload_path.is_symlink() or not payload_path.is_file()
                or _file_sha(payload_path) != intent["payload_sha256"]
                or _read(payload_path) != record["payload"]):
            raise ValueError("原始 payload SHA256／內容與 staged 或 inflight 不一致")
    return {"file_sha256": _file_sha(staged), "payload_digest": _digest(record["payload"])}


def abort_uncommitted(target: Path, batch_id: str, *, payload_path: Path | None = None,
                      acknowledged: bool = False) -> dict:
    """Explicit and idempotent quarantine, with no official Journal updates.

    Crashes after quarantine creation/rename are recoverable by re-invocation.
    A state.json.pending written by an interrupted checkpoint update is NOT
    silently removed: that requires separate inspection.
    """
    if not acknowledged:
        raise ValueError("必須明確 --acknowledge-investigation 才可隔離未提交暫存")
    from review_repair_waves import (REPORT, STATE, _load_state, _write_state,
                                     _digest, _file_sha)
    from review_safety import STAGED
    target = target.resolve()
    state = _load_state(target)
    intent = state.get("inflight")
    if not isinstance(intent, dict):
        # Retries are read-only, and must still verify the archived bytes,
        # immutable receipt, and current formal integrity.
        matching = [x for x in state.get("aborted_transactions", [])
                    if x.get("batch_id") == batch_id]
        if not matching:
            raise ValueError("沒有可取消的 inflight 交易")
        from review_repair_waves import _assert_state_current
        _assert_state_current(target, state)
        last = matching[-1]
        event_id = last.get("event_id")
        if (not isinstance(event_id, str) or len(event_id) != 32
                or any(c not in "0123456789abcdef" for c in event_id)):
            raise ValueError("取消紀錄的交易識別碼無效")
        archive_dir = _safe_folder(target) / event_id
        archive = archive_dir / "staged.json"
        receipt = _read_record(archive_dir / "receipt.json")
        if (archive_dir.is_symlink() or archive.is_symlink() or not archive.is_file()
                or _file_sha(archive) != last.get("staged_sha256")
                or receipt.get("event_id") != event_id
                or receipt.get("staged_sha256") != last.get("staged_sha256")
                or receipt.get("batch_id") != batch_id
                or receipt.get("archived") != last.get("archive")
                or receipt.get("not_formal_journal") is not True):
            raise ValueError("既有隔離封存或稽核收據無法驗證")
        return {"status": "already_aborted", "batch_id": batch_id,
                "archive": last["archive"],
                "notice": "已核對現存封存內容與正式證據，未重複移動"}
    _check_original(target, state, intent, batch_id)
    manifest, evidence = _verify_official_unchanged(target, state, intent)
    quarantine = _safe_folder(target)
    # Bind transaction ID to the original intent AND authenticated Manifest
    # version, so separate failed batches cannot overwrite each other's files.
    identity = {"batch_id": batch_id, "phase": "first_pass",
                "payload_sha256": intent["payload_sha256"],
                "manifest_sha256": evidence["manifest_sha256"],
                "source_snapshot_sha256": evidence["source_snapshot_sha256"]}
    event_id = _digest(identity)[:32]
    folder = quarantine / event_id
    if folder.is_symlink():
        raise ValueError("隔離交易目錄不可為 symbolic link")
    folder.mkdir(exist_ok=True)
    stage = target / REPORT / STAGED
    if stage.is_symlink():
        raise ValueError("staged 目錄不可為 symbolic link")
    original_files = list(stage.iterdir()) if stage.is_dir() else []
    staged = [x for x in original_files if x.suffix == ".json"]
    unexpected = [x for x in original_files if x not in staged]
    if unexpected or len(staged) > 1:
        raise ValueError("staged 含未知檔案或不只一筆交易，禁止取消")
    archived = folder / "staged.json"
    intent_path, receipt_path = folder / "intent.json", folder / "receipt.json"
    if not intent_path.exists():
        if archived.exists() or archived.is_symlink() or receipt_path.exists():
            raise ValueError("隔離紀錄不完整且已包含檔案，需人工調查")
        if len(staged) != 1:
            raise ValueError("缺少唯一待取消的 staged；不能解除 inflight")
        info = _validate_staged(target, state, intent, staged[0], payload_path, manifest)
        prepared = {"schema_version": RECEIPT_VERSION, "identity": identity,
                    "staged_name": staged[0].name, "staged_sha256": info["file_sha256"],
                    "payload_digest": info["payload_digest"],
                    "manifest_sequence": manifest["sequence"],
                    "manifest_head": manifest["head"],
                    "checkpoint_sha256": _digest(state)}
        if list(folder.iterdir()):
            raise ValueError("隔離資料夾已有未知紀錄，拒絕覆蓋")
        _write_new(intent_path, prepared)
    prepared = _read_record(intent_path)
    if (prepared.get("schema_version") != RECEIPT_VERSION
            or prepared.get("identity") != identity
            or prepared.get("manifest_sequence") != manifest["sequence"]
            or prepared.get("manifest_head") != manifest["head"]
            or prepared.get("checkpoint_sha256") != _digest(state)):
        raise ValueError("隔離意圖與目前正式交易或 checkpoint 不一致")
    if (not isinstance(prepared.get("staged_name"), str)
            or not isinstance(prepared.get("staged_sha256"), str)
            or len(prepared["staged_sha256"]) != 64):
        raise ValueError("隔離意圖缺少可信 staged 指紋")
    if len(staged) == 1:
        if archived.exists() or archived.is_symlink():
            raise ValueError("staged 與封存檔同時存在，禁止取消")
        if (staged[0].name != prepared["staged_name"]
                or _file_sha(staged[0]) != prepared["staged_sha256"]):
            raise ValueError("待取消 staged 與已封存隔離意圖不一致")
        # Re-verify stage bytes on retries; the original candidate may be gone.
        if _canonical_sha(_read_record(staged[0])["payload"]) != prepared["payload_digest"]:
            raise ValueError("staged 內容與原先核對的 payload 不一致")
        os.replace(staged[0], archived)
    elif len(staged) == 0:
        if archived.is_symlink() or not archived.is_file():
            raise ValueError("缺少已隔離的 staged 檔案；不得清除 inflight")
    else:
        raise ValueError("staged 狀態異常")
    if archived.is_symlink() or _file_sha(archived) != prepared["staged_sha256"]:
        raise ValueError("隔離的 staged SHA256 不一致")
    if not receipt_path.exists():
        receipt = {"schema_version": RECEIPT_VERSION,
                   "event": "wave2-uncommitted-stage-quarantined",
                   "batch_id": batch_id, "event_id": event_id,
                   "manifest_sequence": manifest["sequence"],
                   "manifest_head": manifest["head"],
                   "manifest_sha256": evidence["manifest_sha256"],
                   "staged_sha256": prepared["staged_sha256"],
                   "payload_sha256": intent["payload_sha256"],
                   "archived": archived.relative_to(target).as_posix(),
                   "recorded_at": datetime.now(timezone.utc).isoformat(),
                   "not_formal_journal": True}
        _write_new(receipt_path, receipt)
    receipt = _read_record(receipt_path)
    if (receipt.get("schema_version") != RECEIPT_VERSION
            or receipt.get("event") != "wave2-uncommitted-stage-quarantined"
            or receipt.get("event_id") != event_id or receipt.get("batch_id") != batch_id
            or receipt.get("staged_sha256") != prepared["staged_sha256"]
            or receipt.get("payload_sha256") != intent["payload_sha256"]
            or receipt.get("manifest_head") != manifest["head"]
            or receipt.get("manifest_sequence") != manifest["sequence"]
            or receipt.get("manifest_sha256") != evidence["manifest_sha256"]
            or receipt.get("archived") != archived.relative_to(target).as_posix()
            or receipt.get("not_formal_journal") is not True):
        raise ValueError("隔離收據與實際封存檔不一致")
    # Recheck before releasing the checkpoint, including the current Journal.
    if _verify_official_unchanged(target, state, intent)[1] != evidence:
        raise ValueError("隔離後正式證據版本發生變更")
    if stage.is_dir() and list(stage.iterdir()):
        raise ValueError("隔離後 staged 目錄仍有待處理內容")
    state["aborted_transactions"] = [*state.get("aborted_transactions", []),
                                      {"batch_id": batch_id, "event_id": event_id,
                                       "archive": receipt["archived"],
                                       "receipt": receipt_path.relative_to(target).as_posix(),
                                       "staged_sha256": prepared["staged_sha256"]}]
    state["inflight"] = None
    _write_state(target / STATE, state)
    return {"status": "aborted_uncommitted", "batch_id": batch_id,
            "manifest_sequence_unchanged": manifest["sequence"],
            "completed_batches_unchanged": len(state["completed_batches"]),
            "archive": receipt["archived"],
            "receipt": receipt_path.relative_to(target).as_posix(),
            "staged_sha256": prepared["staged_sha256"],
            "notice": "僅隔離未入 Journal 的 staged，未寫正式證據；重查原批次後才能重新整合"}
