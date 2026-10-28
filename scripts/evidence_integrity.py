#!/usr/bin/env python3
"""審查資料的單寫者交易日誌與 SHA256 完整性鏈。

雜湊可發現意外或未經工作流程的修改；不使用祕密金鑰，不能抵禦
同時能改寫所有日誌與報告的惡意攻擊者。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

RELATIVE = Path("reports/security-code-review")
ANALYSIS = RELATIVE / "analysis"
INDEX = ANALYSIS / "structure-index.json"
MANIFEST = ANALYSIS / "integrity-manifest.json"
PENDING = ANALYSIS / "integrity-pending.json"
JOURNAL = ANALYSIS / "integrity-journal"
BACKUPS = ANALYSIS / "integrity-backups"
BACKUP_MODE = "content-addressed-v1"
SNAPSHOT = ANALYSIS / "review-snapshot.json"
VERSION = 1
# 只有此清單中正式由整合器寫入的資料可以由交易提交。
TRACKED = (
    "assessment.json",
    "analysis/review-snapshot.json",
    "analysis/rule-closures.json",
    "analysis/control-verifications.json",
    "analysis/decision-audits.json",
    "analysis/adversarial-reviews.json",
    "analysis/recheck-required.json",
    "analysis/first-pass-baseline.json",
)


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _value_hash(value: Any) -> str | None:
    return None if value is None else digest(_json_bytes(value))


def _read(path: Path, default: Any = None) -> Any:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else default


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(_json_bytes(value))
    tmp.replace(path)


def _hash_file(path: Path) -> str | None:
    return digest(path.read_bytes()) if path.is_file() else None


def _path(target: Path, relative: str) -> Path:
    if relative not in TRACKED:
        raise ValueError(f"非受控審查檔案：{relative}")
    path = (target.resolve() / RELATIVE / relative).resolve()
    if not path.is_relative_to((target.resolve() / RELATIVE).resolve()):
        raise ValueError("受控路徑逃逸審查目錄")
    return path


def _hashes(target: Path) -> dict[str, str | None]:
    return {name: _hash_file(_path(target, name)) for name in TRACKED}



def _backup_path(target: Path, sha: str) -> Path:
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
        raise ValueError("備份 SHA256 格式無效")
    return target.resolve() / BACKUPS / sha[:2] / (sha + ".json")


def _backup_bytes(target: Path, sha: str) -> bytes:
    path = _backup_path(target, sha)
    if any(p.is_symlink() for p in (path, path.parent, path.parent.parent, path.parent.parent.parent)):
        raise ValueError("完整性備份路徑包含 symbolic link")
    if not path.is_file():
        raise ValueError(f"找不到 SHA256={sha} 的可信證據內容備份")
    raw = path.read_bytes()
    if digest(raw) != sha:
        raise ValueError(f"證據內容備份 SHA256 不符：{sha}")
    return raw


def _store_backup(target: Path, raw: bytes) -> str:
    sha = digest(raw)
    path = _backup_path(target, sha)
    if path.is_file():
        _backup_bytes(target, sha)
        return sha
    if any(p.is_symlink() for p in (path, path.parent, path.parent.parent, path.parent.parent.parent)):
        raise ValueError("完整性備份路徑包含 symbolic link")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".pending")
    if temporary.is_symlink():
        raise ValueError("備份暫存檔為 symbolic link")
    if temporary.is_file():
        if digest(temporary.read_bytes()) != sha:
            raise ValueError("備份暫存不完整或內容衝突，須人工核對")
    else:
        with temporary.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    if path.exists() or path.is_symlink():
        _backup_bytes(target, sha)
        temporary.unlink(missing_ok=True)
    else:
        temporary.replace(path)
    return sha


def _backup_present_state(target: Path, updates: dict[str, Any] | None = None) -> None:
    """先保護所有未變及將更新的正式證據，再允許 Journal 交易開始。"""
    for name in TRACKED:
        path = _path(target, name)
        if path.is_symlink():
            raise ValueError(f"正式證據路徑包含 symbolic link：{name}")
        if path.is_file():
            _store_backup(target, path.read_bytes())
    for name, value in (updates or {}).items():
        if value is not None:
            _store_backup(target, _json_bytes(value))


def _backup_errors(target: Path, hashes: dict[str, str | None]) -> list[str]:
    issues = []
    for name, sha in hashes.items():
        if sha is None:
            continue
        try:
            _backup_bytes(target, sha)
        except ValueError as exc:
            issues.append(f"資料完整性：{name} 的持久化備份不合格：{exc}")
    return issues


def backup_status(target: Path) -> dict:
    """唯讀查詢最新封存證據是否有可信內容備份。"""
    if not enabled(target):
        return {"ready": False, "errors": ["目前索引未啟用審查交易完整性"]}
    failures = errors(target, verify_files=False, verify_backups=False)
    if failures:
        return {"ready": False, "errors": failures}
    manifest = _read(target / MANIFEST)
    journal = _read(_entry_path(target, manifest["sequence"]))
    problems = _backup_errors(target, journal["file_hashes"])
    return {"ready": not problems, "backup_mode": journal.get("backup_mode", "legacy-hash-only"),
            "errors": problems, "tracked_file_count": sum(v is not None for v in journal["file_hashes"].values())}


def repair_backups(target: Path) -> dict:
    """僅在全部正式證據吻合現有鏈時，將舊版或遺失的備份補齊。"""
    if not enabled(target):
        raise ValueError("目前索引未啟用審查交易完整性")
    troubles = errors(target, verify_backups=False)
    if troubles:
        raise ValueError("備份修補遭拒：先修復正式證據／Journal：" + "；".join(troubles))
    # 只在受控正式檔完全吻合 Journal 時，才可依其 bytes 重建損毀備份。
    # 舊損毀檔先隔離保留供事故鑑識，不能直接覆蓋或當作可信證據。
    for name in TRACKED:
        formal = _path(target, name)
        if not formal.is_file():
            continue
        raw = formal.read_bytes()
        backed = _backup_path(target, digest(raw))
        if any(p.is_symlink() for p in (backed, backed.parent, backed.parent.parent, backed.parent.parent.parent)):
            raise ValueError(f"{name}: 備份路徑包含 symbolic link，拒絕修補")
        if backed.is_file() and digest(backed.read_bytes()) != digest(raw):
            damaged = backed.read_bytes()
            incident = target / ANALYSIS / "integrity-incidents" / (
                "corrupt-backup-" + backed.stem + "-" + digest(damaged) + ".damaged")
            incident.parent.mkdir(parents=True, exist_ok=True)
            if incident.exists():
                if incident.is_symlink() or incident.read_bytes() != damaged:
                    raise ValueError(f"{name}: 事故備份內容衝突，拒絕覆蓋")
                backed.unlink()
            else:
                backed.rename(incident)
    _backup_present_state(target)
    return commit(target, {}, event="backup-checkpoint")


def restore_backups(target: Path, *, allow_replace: bool = False) -> dict:
    """經明確呼叫，只恢復最新可信 Journal 指紋對應的原始 bytes。"""
    target = target.resolve()
    if not enabled(target):
        raise ValueError("目前索引未啟用審查交易完整性")
    troubles = errors(target, verify_files=False, verify_backups=False)
    if troubles:
        raise ValueError("備份復原遭拒：完整性交易鏈不可信：" + "；".join(troubles))
    manifest = _read(target / MANIFEST)
    journal = _read(_entry_path(target, manifest["sequence"]))
    expected = journal["file_hashes"]
    changed = [name for name, sha in expected.items()
               if _hash_file(_path(target, name)) != sha]
    if not changed:
        raise ValueError("目前正式證據與 Journal 完全一致，無需復原")
    payloads = {}
    for name in changed:
        sha = expected[name]
        path = _path(target, name)
        if sha is None:
            raise ValueError(f"{name}: Journal 預期不存在，不允許以復原操作刪除檔案")
        if path.is_symlink() or any(parent.is_symlink() for parent in (path.parent, path.parent.parent)):
            raise ValueError(f"{name}: 復原路徑包含 symbolic link")
        if path.exists() and not allow_replace:
            raise ValueError(f"{name}: 現存內容與 Journal 不同，須明確指定 --allow-damaged-replacement")
        payloads[name] = _backup_bytes(target, sha)
    # 所有備份與覆蓋衝突皆先檢查，再寫入任何正式證據。
    # 現存受損檔案保留原始 bytes 作事故線索，不混入可信 SHA256 證據庫。
    for name in payloads:
        current_path = _path(target, name)
        if current_path.is_file():
            original = current_path.read_bytes()
            damaged_sha = digest(original)
            incident = target / ANALYSIS / "integrity-incidents" / (
                name.replace("/", "__") + "." + damaged_sha + ".damaged")
            incident.parent.mkdir(parents=True, exist_ok=True)
            if incident.exists():
                if incident.is_symlink() or incident.read_bytes() != original:
                    raise ValueError(f"{name}: 已有內容不同的事故備份，拒絕覆寫")
            else:
                with incident.open("xb") as stream:
                    stream.write(original)
                    stream.flush()
                    os.fsync(stream.fileno())
    for name, raw in payloads.items():
        path = _path(target, name)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + ".restore-pending")
        if temporary.exists() or temporary.is_symlink():
            raise ValueError(f"{name}: 復原暫存已存在，須人工核對")
        try:
            with temporary.open("xb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
    troubles = errors(target)
    if troubles:
        raise ValueError("證據恢復後仍有完整性問題：" + "；".join(troubles))
    commit_result = commit(target, {}, event="backup-restore")
    return {"restored_paths": changed, "sequence": commit_result["sequence"],
            "head": commit_result["head"]}


def _entry_path(target: Path, seq: int) -> Path:
    return target / JOURNAL / f"{seq:08d}.json"


def _entry(payload: dict) -> dict:
    data = dict(payload)
    data["entry_hash"] = digest(json.dumps(payload, ensure_ascii=False,
                                           sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return data


def _fp(snapshot: dict) -> str:
    from control_effectiveness import snapshot_fingerprint
    return snapshot_fingerprint(snapshot)


def enabled(target: Path) -> bool:
    obj = _read(target / INDEX, {})
    return isinstance(obj, dict) and obj.get("evidence_integrity_version") == VERSION


def initialize(target: Path, *, explicit: bool = False) -> dict:
    """首次建立受測資料時封存版本；既有資料須明確信任與初始化。"""
    target = target.resolve()
    if not enabled(target):
        raise ValueError("目前索引未啟用審查交易完整性")
    if (target / MANIFEST).exists():
        if errors(target):
            raise ValueError("既有完整性日誌不一致，不能重新初始化掩蓋修改")
        return {"initialized": False, "already_exists": True}
    if (target / PENDING).exists() or list((target / JOURNAL).glob("*.json")):
        raise ValueError("仍有未完成日誌，禁止重新初始化")
    if list((target / ANALYSIS / "staged").glob("*.json")):
        raise ValueError("存在未整合暫存，禁止首次封存")
    snapshot = _read(target / SNAPSHOT)
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("source_hashes"), dict):
        raise ValueError("來源快照不存在；須先執行 analysis_prepare.py")
    assessment = _read(_path(target, "assessment.json"))
    if not isinstance(assessment, dict):
        raise ValueError("assessment.json 不存在，不能封存")
    if not explicit and (assessment.get("findings") or any(
            (c.get("execution") or {}).get("state") == "completed"
            for c in assessment.get("checks", []) if isinstance(c, dict))):
        raise ValueError("既有審查結果不可自動信任；請先核對來源與 Finding，再明確 --seal-integrity")
    hashes = _hashes(target)
    _backup_present_state(target)
    payload = {"schema_version": VERSION, "sequence": 0, "previous": None,
               "event": "initial-seal", "snapshot_fingerprint": _fp(snapshot),
               "file_hashes": hashes, "staged_sha256": {},
               "backup_mode": BACKUP_MODE}
    record = _entry(payload)
    _write(_entry_path(target, 0), record)
    _write(target / MANIFEST, {"schema_version": VERSION, "sequence": 0,
                             "head": record["entry_hash"]})
    return {"initialized": True, "sequence": 0, "head": record["entry_hash"]}


def errors(target: Path, *, verify_files: bool = True, verify_backups: bool = True) -> list[str]:
    if not enabled(target):
        return []
    target = target.resolve()
    manifest = _read(target / MANIFEST)
    if not isinstance(manifest, dict):
        return ["資料完整性：缺少完整性封存；新審查執行 --init，既有資料需核對後執行 --seal-integrity"]
    if (target / PENDING).exists():
        return ["資料完整性：整合交易尚未完成，先執行 --recover-integrity"]
    seq = manifest.get("sequence")
    if type(seq) is not int or seq < 0 or not isinstance(manifest.get("head"), str):
        return ["資料完整性：manifest 格式無效"]
    previous: str | None = None
    last: dict | None = None
    for n in range(seq + 1):
        row = _read(_entry_path(target, n))
        if not isinstance(row, dict):
            return [f"資料完整性：交易日誌缺少序號 {n}"]
        recorded_hash = row.get("entry_hash")
        original = {k: v for k, v in row.items() if k != "entry_hash"}
        if (_entry(original)["entry_hash"] != recorded_hash or row.get("sequence") != n
                or row.get("previous") != previous or row.get("schema_version") != VERSION):
            return [f"資料完整性：交易日誌第 {n} 筆內容或鏈結不一致"]
        boundary = row.get("boundary_attestation")
        if boundary is not None and (
                not isinstance(boundary, dict)
                or set(boundary) != {"schema_version", "run_id", "batch_id", "boundary_level",
                                     "inventory_sha256", "summary_sha256"}
                or boundary.get("schema_version") != 1
                or boundary.get("boundary_level") not in {"L1", "L2", "L3"}
                or not all(isinstance(boundary.get(k), str) and re.fullmatch(r"[0-9a-f]{64}", boundary[k])
                           for k in ("inventory_sha256", "summary_sha256"))):
            return [f"資料完整性：交易日誌第 {n} 筆邊界認證格式異常"]
        archive = row.get("archive_attestation")
        if archive is not None and (
                not isinstance(archive, dict)
                or set(archive) != {"schema_version", "manifest_sha256", "script_count", "allow_cleanup"}
                or archive.get("schema_version") != 1 or archive.get("allow_cleanup") is not False
                or type(archive.get("script_count")) is not int or archive["script_count"] < 0
                or not isinstance(archive.get("manifest_sha256"), str)
                or re.fullmatch(r"[0-9a-f]{64}", archive["manifest_sha256"]) is None):
            return [f"資料完整性：交易日誌第 {n} 筆舊腳本封存認證異常"]
        if set(row.get("file_hashes", {})) != set(TRACKED):
            return [f"資料完整性：交易日誌第 {n} 筆受控檔案清單異常"]
        previous, last = recorded_hash, row
    if previous != manifest["head"]:
        return ["資料完整性：manifest 與最後交易日誌不一致"]
    if _entry_path(target, seq + 1).is_file():
        return ["資料完整性：存在未對應 manifest 的額外交易日誌"]
    if last is None:
        return ["資料完整性：找不到完整交易"]
    snapshot = _read(target / SNAPSHOT)
    if verify_files and (not isinstance(snapshot, dict) or last["snapshot_fingerprint"] != _fp(snapshot)):
        return ["資料完整性：已封存來源快照與目前不一致"]
    issues = []
    if verify_files:
        now = _hashes(target)
        issues.extend(f"資料完整性：{p} 與交易日誌的 SHA256 不一致，禁止直接覆寫"
                      for p in TRACKED if now[p] != last["file_hashes"][p])
    if verify_backups and last.get("backup_mode") == BACKUP_MODE:
        issues.extend(_backup_errors(target, last["file_hashes"]))
    return issues


def commit(target: Path, updates: dict[str, Any], *, event: str,
           staged_paths: list[Path] | None = None,
           new_snapshot: dict | None = None,
           boundary_attestation: dict | None = None,
           archive_attestation: dict | None = None) -> dict:
    """先寫 ahead-log，再寫受控檔案；中斷後需明確 recovery。"""
    target = target.resolve()
    if not enabled(target):
        raise ValueError("交易日誌未啟用")
    troubles = errors(target)
    if troubles:
        raise ValueError("；".join(troubles))
    if not set(updates).issubset(TRACKED):
        raise ValueError("嘗試修改未受控審查檔案")
    base = _read(target / MANIFEST)
    prior = _read(_entry_path(target, base["sequence"]))
    after_hashes = dict(prior["file_hashes"])
    for relative, value in updates.items():
        after_hashes[relative] = _value_hash(value)
    staged = {}
    for p in staged_paths or []:
        p = p.resolve()
        folder = (target / ANALYSIS / "staged").resolve()
        if not p.is_relative_to(folder) or not p.is_file() or p.suffix != ".json":
            raise ValueError("交易暫存路徑不在指定 staged 目錄")
        staged[p.name] = _hash_file(p)
    _backup_present_state(target, updates)
    current_snapshot = new_snapshot if new_snapshot is not None else _read(target / SNAPSHOT)
    if not isinstance(current_snapshot, dict):
        raise ValueError("交易快照不存在")
    next_seq = base["sequence"] + 1
    pending = {
        "schema_version": VERSION, "sequence": next_seq, "previous": base["head"],
        "event": event, "snapshot_fingerprint": _fp(current_snapshot),
        "before_hashes": prior["file_hashes"], "after_hashes": after_hashes,
        "updates": updates, "staged_sha256": staged,
        "backup_mode": BACKUP_MODE,
    }
    if boundary_attestation is not None:
        if (not isinstance(boundary_attestation, dict)
                or set(boundary_attestation) != {"schema_version", "run_id", "batch_id",
                                                 "boundary_level", "inventory_sha256", "summary_sha256"}
                or boundary_attestation.get("schema_version") != 1
                or boundary_attestation.get("boundary_level") not in {"L1", "L2", "L3"}
                or not all(isinstance(boundary_attestation.get(k), str)
                           and re.fullmatch(r"[0-9a-f]{64}", boundary_attestation[k])
                           for k in ("inventory_sha256", "summary_sha256"))):
            raise ValueError("P0 邊界認證契約無效，拒絕交易")
        pending["boundary_attestation"] = boundary_attestation
    if archive_attestation is not None:
        if (event != "legacy-script-archive" or not isinstance(archive_attestation, dict)
                or set(archive_attestation) != {"schema_version", "manifest_sha256", "script_count", "allow_cleanup"}
                or archive_attestation.get("schema_version") != 1
                or archive_attestation.get("allow_cleanup") is not False
                or type(archive_attestation.get("script_count")) is not int
                or archive_attestation["script_count"] < 0
                or not isinstance(archive_attestation.get("manifest_sha256"), str)
                or re.fullmatch(r"[0-9a-f]{64}", archive_attestation["manifest_sha256"]) is None):
            raise ValueError("舊腳本封存交易契約無效")
        pending["archive_attestation"] = archive_attestation
    _write(target / PENDING, pending)
    return recover(target)


def recover(target: Path) -> dict:
    """不接受第三種檔案內容；僅重播已封存且可核對的中斷交易。"""
    target = target.resolve()
    pending = _read(target / PENDING)
    if not isinstance(pending, dict):
        raise ValueError("沒有待復原交易")
    manifest = _read(target / MANIFEST)
    if not isinstance(manifest, dict):
        raise ValueError("完整性 manifest 不存在")
    before, after = pending.get("before_hashes"), pending.get("after_hashes")
    updates = pending.get("updates")
    if (not isinstance(before, dict) or not isinstance(after, dict)
            or set(before) != set(TRACKED) or set(after) != set(TRACKED)
            or not isinstance(updates, dict) or not set(updates).issubset(TRACKED)):
        raise ValueError("待復原交易資料格式或受控範圍無效")
    previous = _read(_entry_path(target, pending.get("sequence", 0) - 1))
    if (not isinstance(previous, dict)
            or previous.get("entry_hash") != pending.get("previous")
            or previous.get("file_hashes") != before
            or _entry({k: v for k, v in previous.items()
                       if k != "entry_hash"})["entry_hash"] != previous.get("entry_hash")):
        raise ValueError("復原遭拒：先前交易鏈與 SHA256 不一致")
    record_data = {"schema_version": VERSION, "sequence": pending["sequence"],
                   "previous": pending["previous"], "event": pending["event"],
                   "snapshot_fingerprint": pending["snapshot_fingerprint"],
                   "file_hashes": after, "staged_sha256": pending["staged_sha256"]}
    if pending.get("boundary_attestation") is not None:
        record_data["boundary_attestation"] = pending["boundary_attestation"]
    if pending.get("archive_attestation") is not None:
        record_data["archive_attestation"] = pending["archive_attestation"]
    if pending.get("backup_mode") == BACKUP_MODE:
        record_data["backup_mode"] = BACKUP_MODE
        issues = _backup_errors(target, after)
        if issues:
            raise ValueError("復原遭拒：交易內容備份不完整：" + "；".join(issues))
    row = _entry(record_data)
    committed = (manifest.get("sequence") == pending["sequence"]
                 and manifest.get("head") == row["entry_hash"])
    if not committed and (pending.get("previous") != manifest.get("head")
                          or pending.get("sequence") != manifest.get("sequence", -1) + 1):
        raise ValueError("待復原交易與已提交的完整性鏈不同，拒絕操作")
    if committed and _read(_entry_path(target, pending["sequence"])) != row:
        raise ValueError("已提交交易與日誌內容不同，不允許自動清理")
    for relative in TRACKED:
        now = _hash_file(_path(target, relative))
        if (now != after[relative] if committed else now not in {before[relative], after[relative]}):
            raise ValueError(f"復原遭拒：{relative} 已被第三種內容修改，須人工核對")
        if relative in updates and _value_hash(updates[relative]) != after[relative]:
            raise ValueError(f"復原遭拒：{relative} 交易內容的 SHA256 無效")
        if relative not in updates and before[relative] != after[relative]:
            raise ValueError(f"復原遭拒：{relative} 未授權變更")
    folder = (target / ANALYSIS / "staged").resolve()
    for filename, sha in (pending.get("staged_sha256") or {}).items():
        if (not isinstance(filename, str) or Path(filename).name != filename
                or (_hash_file(folder / filename) not in ({sha, None} if committed else {sha}))):
            raise ValueError(f"復原遭拒：暫存 {filename} 遭修改或消失")
    if not committed:
        for relative, value in updates.items():
            p = _path(target, relative)
            if value is None:
                p.unlink(missing_ok=True)
            else:
                _write(p, value)
    journal = _entry_path(target, pending["sequence"])
    if journal.is_file() and _read(journal) != row:
        raise ValueError("復原遭拒：已存在不同內容的交易日誌")
    _write(journal, row)
    _write(target / MANIFEST, {"schema_version": VERSION,
                             "sequence": pending["sequence"], "head": row["entry_hash"]})
    for filename in (pending.get("staged_sha256") or {}):
        (folder / filename).unlink(missing_ok=True)
    (target / PENDING).unlink()
    return {"sequence": pending["sequence"], "head": row["entry_hash"],
            "event": pending["event"], "updated": sorted(updates)}
