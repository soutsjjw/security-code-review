#!/usr/bin/env python3
"""審查資料的單寫者交易日誌與 SHA256 完整性鏈。

雜湊可發現意外或未經工作流程的修改；不使用祕密金鑰，不能抵禦
同時能改寫所有日誌與報告的惡意攻擊者。
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

RELATIVE = Path("reports/security-code-review")
ANALYSIS = RELATIVE / "analysis"
INDEX = ANALYSIS / "structure-index.json"
MANIFEST = ANALYSIS / "integrity-manifest.json"
PENDING = ANALYSIS / "integrity-pending.json"
JOURNAL = ANALYSIS / "integrity-journal"
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
    payload = {"schema_version": VERSION, "sequence": 0, "previous": None,
               "event": "initial-seal", "snapshot_fingerprint": _fp(snapshot),
               "file_hashes": hashes, "staged_sha256": {}}
    record = _entry(payload)
    _write(_entry_path(target, 0), record)
    _write(target / MANIFEST, {"schema_version": VERSION, "sequence": 0,
                             "head": record["entry_hash"]})
    return {"initialized": True, "sequence": 0, "head": record["entry_hash"]}


def errors(target: Path) -> list[str]:
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
    if not isinstance(snapshot, dict) or last["snapshot_fingerprint"] != _fp(snapshot):
        return ["資料完整性：已封存來源快照與目前不一致"]
    now = _hashes(target)
    return [f"資料完整性：{p} 與交易日誌的 SHA256 不一致，禁止直接覆寫"
            for p in TRACKED if now[p] != last["file_hashes"][p]]


def commit(target: Path, updates: dict[str, Any], *, event: str,
           staged_paths: list[Path] | None = None,
           new_snapshot: dict | None = None) -> dict:
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
    current_snapshot = new_snapshot if new_snapshot is not None else _read(target / SNAPSHOT)
    if not isinstance(current_snapshot, dict):
        raise ValueError("交易快照不存在")
    next_seq = base["sequence"] + 1
    pending = {
        "schema_version": VERSION, "sequence": next_seq, "previous": base["head"],
        "event": event, "snapshot_fingerprint": _fp(current_snapshot),
        "before_hashes": prior["file_hashes"], "after_hashes": after_hashes,
        "updates": updates, "staged_sha256": staged,
    }
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
    row = _entry({"schema_version": VERSION, "sequence": pending["sequence"],
                  "previous": pending["previous"], "event": pending["event"],
                  "snapshot_fingerprint": pending["snapshot_fingerprint"],
                  "file_hashes": after, "staged_sha256": pending["staged_sha256"]})
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
