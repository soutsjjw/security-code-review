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
import review_waves_state as ws
from review_core import canonical_digest as _digest, file_sha256 as _file_sha, REPORT_ROOT

QUARANTINE = REPORT_ROOT / "logs/repair-waves/aborted"
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
    for folder in (root / "reports", root / REPORT_ROOT,
                   root / REPORT_ROOT / "logs",
                   root / REPORT_ROOT / "logs/repair-waves", base):
        if folder.is_symlink():
            raise ValueError("隔離目錄包含 symbolic link")
    base.mkdir(parents=True, exist_ok=True)
    return base


def _verify_official_unchanged(target: Path, state: dict, intent: dict) -> tuple[dict, dict]:
    from evidence_integrity import MANIFEST, PENDING
    if (target / PENDING).exists() or (target / PENDING).is_symlink():
        raise ValueError("存在完整性待提交交易，禁止取消；先處理正式復原")
    evidence = ws._evidence_state(target)  # checks Journal chain and ALL tracked hashes
    old = intent.get("prior_evidence")
    if (not isinstance(old, dict) or evidence != old
            or evidence != state.get("last_evidence")):
        raise ValueError("正式 Manifest／Journal／追蹤工件與交易前版本不同，禁止取消")
    manifest = _read_record(target / MANIFEST)
    if (not isinstance(manifest.get("head"), str)
            or type(manifest.get("sequence")) is not int or manifest["sequence"] < 0):
        raise ValueError("Manifest sequence/head 格式不合法")
    fingerprints = ws._formal_fingerprints(target)
    if (fingerprints != intent.get("prior_fingerprints")
            or fingerprints != state.get("formal_fingerprints")):
        raise ValueError("正式逐條證據已變更，禁止取消")
    return manifest, evidence


def _check_original(target: Path, state: dict, intent: dict, batch_id: str) -> None:
    if (state.get("phase") != "first_pass" or intent.get("phase") != "first_pass"
            or intent.get("batch_id") != batch_id
            or not isinstance(intent.get("payload_sha256"), str)
            or len(intent["payload_sha256"]) != 64):
        raise ValueError("僅允許取消明確指定的第一輪未提交 Wave 2 批次")
    expected = ws._next_batch(state)
    if not expected or expected.get("batch_id") != batch_id:
        raise ValueError("取消批次已結案、依賴不符或不是目前執行批次")


def _validate_staged(target: Path, state: dict, intent: dict,
                     staged: Path, payload_path: Path | None, manifest: dict,
                     *, expected_staged_sha256: str | None = None,
                     allow_unbound_legacy: bool = False) -> dict:
    from review_snapshot import STAGED, SNAPSHOT
    source = target / ws.REPORT / STAGED
    if source.is_symlink() or staged.is_symlink() or not staged.is_file():
        raise ValueError("staged 不是可信的一般檔案")
    if staged.parent.resolve() != source.resolve() or staged.suffix != ".json":
        raise ValueError("staged 檔案不在正式暫存目錄")
    record = ws._read(staged)
    if set(record) != {"snapshot_git_revision", "source_hashes", "payload", "integrity_head"}:
        raise ValueError("staged 欄位異常，不得取消")
    serialized = json.dumps(record, ensure_ascii=False, sort_keys=True)
    expected_name = hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:24] + ".json"
    if staged.name != expected_name:
        raise ValueError("staged 檔名與正式 Stage 內容指紋不一致")
    snapshot = ws._read(target / ws.REPORT / SNAPSHOT)
    if (record["snapshot_git_revision"] != snapshot.get("git_revision")
            or record["source_hashes"] != snapshot.get("source_hashes")
            or record["integrity_head"] != manifest["head"]):
        raise ValueError("staged 的來源快照或 Manifest head 不一致")
    expected_semantic = intent.get("payload_digest")
    if expected_semantic is not None and expected_semantic != _digest(record["payload"]):
        raise ValueError("staged payload 與 inflight 內容指紋不一致")
    if payload_path is None and expected_semantic is None:
        if not allow_unbound_legacy:
            raise ValueError("舊版 inflight 必須提供原始 --payload 以核對 SHA256；或額外明確授權 staged-only 隔離")
        if (not isinstance(expected_staged_sha256, str)
                or len(expected_staged_sha256) != 64
                or any(c not in "0123456789abcdef" for c in expected_staged_sha256)
                or _file_sha(staged) != expected_staged_sha256):
            raise ValueError("staged-only 需要與唯一暫存檔完全一致的 64 字 SHA256")
    if payload_path is not None:
        if (payload_path.is_symlink() or not payload_path.is_file()
                or _file_sha(payload_path) != intent["payload_sha256"]
                or ws._read(payload_path) != record["payload"]):
            raise ValueError("原始 payload SHA256／內容與 staged 或 inflight 不一致")
    return {"file_sha256": _file_sha(staged),
            "payload_digest": _digest(record["payload"]),
            "raw_payload_verified": payload_path is not None,
            "legacy_unbound": payload_path is None and expected_semantic is None}



def inspect_uncommitted(target: Path, batch_id: str, *,
                        payload_path: Path | None = None,
                        expected_staged_sha256: str | None = None,
                        allow_unbound_legacy: bool = False) -> dict:
    """Read-only verification of a failed Stage before requesting cancellation.

    Never creates quarantine directories or changes a checkpoint. A legacy
    inflight may be well-formed yet unabortable until its exact source payload
    bytes are supplied.
    """
    from review_snapshot import STAGED
    target = target.resolve()
    state = ws._load_state(target)
    intent = state.get("inflight")
    if not isinstance(intent, dict):
        raise ValueError("不存在可核對的 inflight 交易")
    _check_original(target, state, intent, batch_id)
    manifest, evidence = _verify_official_unchanged(target, state, intent)
    staging = target / ws.REPORT / STAGED
    if staging.is_symlink() or not staging.is_dir():
        raise ValueError("正式 staged 目錄不存在或包含 symbolic link")
    files = list(staging.iterdir())
    if len(files) != 1 or files[0].suffix != ".json":
        raise ValueError("需要唯一的 JSON staged；不得混入其他暫存")
    stage = files[0]
    needs_original = payload_path is None and intent.get("payload_digest") is None
    legacy_authorized = bool(needs_original and allow_unbound_legacy
                             and expected_staged_sha256 is not None)
    # Verify all non-payload properties even when legacy raw bytes are missing;
    # this cannot authorize cancellation until the raw payload is supplied.
    if needs_original and not legacy_authorized:
        from review_snapshot import SNAPSHOT
        record = ws._read(stage)
        if (stage.is_symlink() or not stage.is_file()
                or set(record) != {"snapshot_git_revision", "source_hashes",
                                   "payload", "integrity_head"}):
            raise ValueError("staged 的結構或檔案型別無效")
        serialization = json.dumps(record, ensure_ascii=False, sort_keys=True)
        if stage.name != hashlib.sha256(serialization.encode("utf-8")).hexdigest()[:24] + ".json":
            raise ValueError("staged 的檔名與內容指紋不同")
        snapshot = ws._read(target / ws.REPORT / SNAPSHOT)
        if (record["integrity_head"] != manifest["head"]
                or record["snapshot_git_revision"] != snapshot["git_revision"]
                or record["source_hashes"] != snapshot["source_hashes"]):
            raise ValueError("staged 的 Manifest head／來源快照不吻合")
    else:
        _validate_staged(target, state, intent, stage, payload_path, manifest,
                         expected_staged_sha256=expected_staged_sha256,
                         allow_unbound_legacy=allow_unbound_legacy)
    # Must not create any files during inspection. If an aborted intent exists,
    # a separate cancellation invocation reconciles it after SHA verification.
    ready = not needs_original or legacy_authorized
    return {"status": ("needs_original_payload" if not ready else
                       "ready_to_abort_unbound" if legacy_authorized else "ready_to_abort"),
            "batch_id": batch_id, "manifest_sequence": manifest["sequence"],
            "manifest_head": manifest["head"],
            "manifest_sha256": evidence["manifest_sha256"],
            "staged_count": 1, "staged_file": stage.relative_to(target).as_posix(),
            "staged_sha256": _file_sha(stage),
            "inflight_payload_sha256": intent["payload_sha256"],
            "requires_original_payload": needs_original and not legacy_authorized,
            "raw_payload_verified": payload_path is not None,
            "legacy_unbound_staged_only": legacy_authorized,
            "can_abort": ready,
            "read_only": True,
            "note": ("此 staged-only 例外只能證實唯一暫存檔的 SHA256，"
                     "不能證明它與 inflight 原始 payload bytes 相同；仍需正式授權"
                     if legacy_authorized else
                     "舊版 checkpoint 無法從 staged 還原原始 JSON bytes；"
                     "請提供原始 payload 或另行明確授權 staged-only 隔離"
                     if needs_original else
                     "只完成唯讀對帳；實際隔離仍需明確 --acknowledge-investigation")}


def abort_uncommitted(target: Path, batch_id: str, *, payload_path: Path | None = None,
                      acknowledged: bool = False,
                      expected_staged_sha256: str | None = None,
                      allow_unbound_legacy: bool = False) -> dict:
    """Explicit and idempotent quarantine, with no official Journal updates.

    Crashes after quarantine creation/rename are recoverable by re-invocation.
    A state.json.pending written by an interrupted checkpoint update is NOT
    silently removed: that requires separate inspection.
    """
    if not acknowledged:
        raise ValueError("必須明確 --acknowledge-investigation 才可隔離未提交暫存")
    from review_snapshot import STAGED
    target = target.resolve()
    state = ws._load_state(target)
    intent = state.get("inflight")
    if not isinstance(intent, dict):
        # Retries are read-only, and must still verify the archived bytes,
        # immutable receipt, and current formal integrity.
        matching = [x for x in state.get("aborted_transactions", [])
                    if x.get("batch_id") == batch_id]
        if not matching:
            raise ValueError("沒有可取消的 inflight 交易")
        ws._assert_state_current(target, state)
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
    stage = target / ws.REPORT / STAGED
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
        info = _validate_staged(
            target, state, intent, staged[0], payload_path, manifest,
            expected_staged_sha256=expected_staged_sha256,
            allow_unbound_legacy=allow_unbound_legacy)
        prepared = {"schema_version": RECEIPT_VERSION, "identity": identity,
                    "staged_name": staged[0].name, "staged_sha256": info["file_sha256"],
                    "payload_digest": info["payload_digest"],
                    "raw_payload_verified": info["raw_payload_verified"],
                    "legacy_unbound": info["legacy_unbound"],
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
    if prepared.get("legacy_unbound", False):
        if (not allow_unbound_legacy
                or expected_staged_sha256 != prepared["staged_sha256"]):
            raise ValueError("既有 staged-only 例外在中斷恢復時仍須提供相同 SHA256 與明確例外授權")
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
                   "raw_payload_verified": prepared.get("raw_payload_verified", False),
                   "legacy_unbound": prepared.get("legacy_unbound", False),
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
            or receipt.get("legacy_unbound") != prepared.get("legacy_unbound", False)
            or receipt.get("raw_payload_verified") != prepared.get("raw_payload_verified", False)
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
    ws._write_state(target / ws.STATE, state)
    return {"status": "aborted_uncommitted", "batch_id": batch_id,
            "manifest_sequence_unchanged": manifest["sequence"],
            "completed_batches_unchanged": len(state["completed_batches"]),
            "archive": receipt["archived"],
            "receipt": receipt_path.relative_to(target).as_posix(),
            "staged_sha256": prepared["staged_sha256"],
            "legacy_unbound_staged_only": prepared.get("legacy_unbound", False),
            "notice": "僅隔離未入 Journal 的 staged，未寫正式證據；重查原批次後才能重新整合"}
