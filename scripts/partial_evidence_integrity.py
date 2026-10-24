#!/usr/bin/env python3
"""分類審查獨立證據交易：預寫日誌、SHA256 鏈與排他鎖。

每個分類擁有獨立封存與受控提交；交易中斷保持 pending 等待明確復原。
不宣稱多檔案具備作業系統級原子性或目前已能自動復原。

無密鑰雜湊用於發現意外或未授權的工作流程外修改；
若攻擊者能同時改寫檔案與整條日誌鏈，不能將其視為數位簽章。
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Iterator

from partial_review import _artifact, _category_dir, _atomic, _snapshot, read_category
from review_scope import CATEGORY_COUNTS, ScopeError, load_catalog

VERSION = 1
MANIFEST = Path("analysis/integrity-manifest.json")
PENDING = Path("analysis/integrity-pending.json")
JOURNAL = Path("analysis/integrity-journal")
LOCK = Path("analysis/integrity.lock")
STAGED = Path("analysis/staged/pending.json")
HISTORY = Path("analysis/second-pass-history")

# 本清單與分類 review/second-pass 寫入的所有固定證據相對路徑對應。
# 尚未存在的檔案以 null SHA256 記錄，不得以空物件取代缺少資料。
TRACKED = (
    "assessment.json",
    "project.json",
    "analysis/source-snapshot.json",
    "analysis/rule-closures.json",
    "analysis/control-verifications.json",
    "analysis/decision-audits.json",
    "analysis/adversarial-reviews.json",
    "analysis/first-pass-baseline.json",
)
_HISTORY_NAME = re.compile(r"^[0-9a-f]{32}\.json$")
_HASH = re.compile(r"^[0-9a-f]{64}$")


class IntegrityError(ScopeError):
    """分類完整性契約或鎖定失敗；不應自動刪除／重新封存資料。"""


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _entry(fields: dict[str, Any]) -> dict[str, Any]:
    raw = json.dumps(fields, ensure_ascii=False, sort_keys=True,
                     separators=(",", ":")).encode("utf-8")
    return {**fields, "entry_hash": _sha(raw)}


def _file_hash(path: Path) -> str | None:
    return _sha(path.read_bytes()) if path.is_file() else None


def _read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _journal_path(root: Path, category: str, seq: int) -> Path:
    if type(seq) is not int or seq < 0:
        raise IntegrityError("交易序號無效")
    return _artifact(root, category, JOURNAL / f"{seq:08d}.json")


def _paths(root: Path, category: str) -> dict[str, Path]:
    if category not in CATEGORY_COUNTS:
        raise IntegrityError(f"未知審查分類：{category}")
    paths = {name: _artifact(root, category, name) for name in TRACKED}
    history = _artifact(root, category, HISTORY)
    if history.exists():
        if not history.is_dir():
            raise IntegrityError("第二輪修訂歷史不是目錄")
        for child in history.iterdir():
            if (not child.is_file() or not _HISTORY_NAME.fullmatch(child.name)
                    or child.is_symlink()):
                raise IntegrityError("第二輪修訂歷史包含未知或不安全檔案")
            name = (HISTORY / child.name).as_posix()
            paths[name] = _artifact(root, category, name)
    return paths


def _hashes(root: Path, category: str) -> dict[str, str | None]:
    return {name: _file_hash(path) for name, path in sorted(_paths(root, category).items())}


def _valid_hashes(value: Any) -> bool:
    return (isinstance(value, dict) and set(TRACKED) <= set(value)
            and all(isinstance(k, str) and (
                k in TRACKED or k.startswith(HISTORY.as_posix() + "/")
                and _HISTORY_NAME.fullmatch(k[len(HISTORY.as_posix()) + 1:]))
                for k in value)
            and all(v is None or isinstance(v, str) and _HASH.fullmatch(v)
                    for v in value.values()))


@contextmanager
def locked(root: Path, category: str) -> Iterator[None]:
    """單一分類短期寫鎖；鎖尚存在時 fail-closed，不能自動解鎖未知持有者。"""
    _category_dir(root, category)
    path = _artifact(root, category, LOCK)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise IntegrityError(f"{category}: 交易鎖已存在，須確認持有者後處理：{path}") from exc
    fingerprint = os.fstat(fd)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(f"pid={os.getpid()}\n")
            handle.flush()
            os.fsync(handle.fileno())
        yield
    finally:
        # 不可刪除別的工作替換的鎖；同名新 inode 不等於本次取得的鎖。
        try:
            current = path.stat(follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if (current is not None and (current.st_dev, current.st_ino)
                == (fingerprint.st_dev, fingerprint.st_ino)):
            path.unlink()


def errors(root: Path, category: str) -> list[str]:
    """完整性驗證為唯讀；不會因缺少封存自動信任舊資料。"""
    try:
        return _errors(root, category)
    except (OSError, ValueError, TypeError, KeyError, ScopeError) as exc:
        return [f"{category}: 完整性驗證失敗：{exc}"]


def _errors(root: Path, category: str) -> list[str]:
    _category_dir(root, category)
    manifest_path = _artifact(root, category, MANIFEST)
    pending_path = _artifact(root, category, PENDING)
    journal_dir = _artifact(root, category, JOURNAL)
    if pending_path.exists():
        return [f"{category}: 發現未完成的完整性交易；不得直接整合或重新封存"]
    if not manifest_path.is_file():
        return [f"{category}: 缺少完整性初始封存，禁止直接將既有證據視為可信"]
    manifest = _read(manifest_path)
    if (not isinstance(manifest, dict) or manifest.get("schema_version") != VERSION
            or manifest.get("category") != category
            or type(manifest.get("sequence")) is not int
            or manifest["sequence"] < 0
            or not isinstance(manifest.get("head"), str)):
        return [f"{category}: 完整性 Manifest 格式或分類身分無效"]
    if not journal_dir.is_dir():
        return [f"{category}: 缺少交易日誌目錄"]
    seq = manifest["sequence"]
    expected = {f"{n:08d}.json" for n in range(seq + 1)}
    actual = {p.name for p in journal_dir.iterdir()}
    if actual != expected:
        return [f"{category}: 交易日誌存在缺漏、額外或非預期項目"]
    previous: str | None = None
    last: dict | None = None
    for n in range(seq + 1):
        row = _read(_journal_path(root, category, n))
        if not isinstance(row, dict):
            return [f"{category}: 交易日誌 {n} 的格式不正確"]
        recorded = row.get("entry_hash")
        raw = {k: v for k, v in row.items() if k != "entry_hash"}
        if (row.get("schema_version") != VERSION or row.get("category") != category
                or type(row.get("sequence")) is not int or row["sequence"] != n
                or row.get("previous") != previous
                or recorded != _entry(raw)["entry_hash"]
                or not _valid_hashes(row.get("file_hashes"))
                or not isinstance(row.get("source_snapshot_sha256"), str)
                or not _HASH.fullmatch(row["source_snapshot_sha256"])):
            return [f"{category}: 交易日誌 {n} 內容、受控檔案或 SHA256 鏈異常"]
        previous, last = recorded, row
    if last is None or manifest["head"] != previous:
        return [f"{category}: Manifest 與交易日誌 head 不一致"]
    current = read_category(root, category, load_catalog())
    snap = _snapshot(root)
    if (manifest.get("source_snapshot_sha256") != current["source_snapshot_sha256"]
            or last["source_snapshot_sha256"] != snap["fingerprint"]):
        return [f"{category}: 已封存來源快照與實際來源不一致"]
    now = _hashes(root, category)
    recorded = last["file_hashes"]
    if set(now) != set(recorded):
        return [f"{category}: 受控檔案清單變更，含新增或刪除的第二輪修訂歷史"]
    mismatched = [name for name in now if now[name] != recorded[name]]
    return [f"{category}: {name} 與已封存 SHA256 不符，禁止直接覆寫" for name in mismatched]


def initialize(root: Path, category: str, *, explicit: bool = False) -> dict[str, Any]:
    """首次封存乾淨的分類狀態；既有進度須先人工核對再明確指定 explicit。"""
    _category_dir(root, category)
    with locked(root, category):
        manifest = _artifact(root, category, MANIFEST)
        pending = _artifact(root, category, PENDING)
        journal = _artifact(root, category, JOURNAL)
        staged = _artifact(root, category, STAGED)
        if manifest.is_file():
            problems = errors(root, category)
            if problems:
                raise IntegrityError("；".join(problems))
            obj = _read(manifest)
            return {"initialized": False, "already_exists": True,
                    "category": category, "sequence": obj["sequence"], "head": obj["head"]}
        if (pending.exists() or journal.exists() and any(journal.iterdir())
                or staged.exists()):
            raise IntegrityError(f"{category}: 存在未完成交易／暫存，禁止直接封存掩蓋證據")
        assessment = read_category(root, category, load_catalog())
        if (assessment.get("findings") or assessment.get("file_reviews")
                or any((row.get("execution") or {}).get("state") != "pending"
                       for row in assessment["checks"])):
            if not explicit:
                raise IntegrityError(f"{category}: 既有審查紀錄須人工核對後明確封存")
        paths = _paths(root, category)
        other_evidence = (any(paths[k].is_file() for k in TRACKED[3:])
                          or any(name.startswith(HISTORY.as_posix() + "/")
                                 for name in paths))
        if other_evidence and not explicit:
            raise IntegrityError(f"{category}: 已有安全／第二輪證據，須人工核對後明確封存")
        snap = _snapshot(root)
        if assessment["source_snapshot_sha256"] != snap["fingerprint"]:
            raise IntegrityError(f"{category}: Git／來源快照已更改，禁止封存")
        hashes = _hashes(root, category)
        body = {"schema_version": VERSION, "category": category, "sequence": 0,
                "previous": None, "event": "initial-seal",
                "source_snapshot_sha256": snap["fingerprint"], "file_hashes": hashes}
        row = _entry(body)
        _atomic(_journal_path(root, category, 0), row)
        _atomic(manifest, {"schema_version": VERSION, "category": category,
                           "sequence": 0, "head": row["entry_hash"],
                           "source_snapshot_sha256": snap["fingerprint"]})
        problems = errors(root, category)
        if problems:
            raise IntegrityError("初始封存後完整性驗證失敗：" + "；".join(problems))
        return {"initialized": True, "category": category, "sequence": 0,
                "head": row["entry_hash"]}


def _json_bytes(value: Any) -> bytes:
    """與 partial_review._atomic 相同的 JSON bytes，避免指紋與實際落盤不一致。"""
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def commit(root: Path, category: str, updates: dict[str, Any], *,
           event: str, staged_path: Path | None = None,
           staged_sha256: str | None = None) -> dict[str, Any]:
    """在分類鎖內建立 ahead-log，再原子替換各受控檔案並封存日誌鏈。

    任何寫入失敗都保留 integrity-pending.json 及 staged 來源，不會宣稱成功。
    中斷後的恢復屬獨立明確操作，此函式不重播不明交易。
    """
    if not isinstance(updates, dict) or not updates or not isinstance(event, str) or not event:
        raise IntegrityError("交易必須包含非空受控更新與事件名稱")
    if staged_path is None and staged_sha256 is not None:
        raise IntegrityError("缺少 staged 路徑")
    if staged_path is not None and (not isinstance(staged_sha256, str)
                                    or not _HASH.fullmatch(staged_sha256)):
        raise IntegrityError("staged SHA256 無效")

    with locked(root, category):
        problems = errors(root, category)
        if problems:
            raise IntegrityError("；".join(problems))
        manifest_path = _artifact(root, category, MANIFEST)
        pending_path = _artifact(root, category, PENDING)
        manifest = _read(manifest_path)
        prev = _read(_journal_path(root, category, manifest["sequence"]))
        before = prev["file_hashes"]
        if _hashes(root, category) != before:
            raise IntegrityError("提交前證據與已封存版本不一致")
        candidate_paths = _paths(root, category)
        normalized: dict[str, Any] = {}
        for relative, obj in updates.items():
            if not isinstance(relative, str) or not isinstance(obj, (dict, list)):
                raise IntegrityError("交易僅接受合法 JSON 物件／陣列證據")
            allowed = relative in TRACKED or (
                relative.startswith(HISTORY.as_posix() + "/")
                and _HISTORY_NAME.fullmatch(relative[len(HISTORY.as_posix()) + 1:]))
            if not allowed:
                raise IntegrityError(f"嘗試修改未受控分類工件：{relative}")
            guarded = _artifact(root, category, relative)
            if relative not in candidate_paths and guarded.exists():
                raise IntegrityError(f"未知或不合法的修訂歷史：{relative}")
            normalized[relative] = obj
        staged: dict[str, str] = {}
        if staged_path is not None:
            expected = _artifact(root, category, STAGED)
            if staged_path != expected or not expected.is_file():
                raise IntegrityError("staged 交易檔案不存在或不在分類私有路徑")
            if _file_hash(expected) != staged_sha256:
                raise IntegrityError("staged 批次內容在預備交易後遭修改")
            staged[STAGED.as_posix()] = staged_sha256
        elif _artifact(root, category, STAGED).exists():
            raise IntegrityError("存在未整合的 staged 交易；禁止其他安全證據提交")

        after = dict(before)
        for relative, obj in normalized.items():
            after[relative] = _sha(_json_bytes(obj))
        if not _valid_hashes(after):
            raise IntegrityError("交易受控檔案清單不合法")
        snapshot = _snapshot(root)
        assessment_path = _artifact(root, category, "assessment.json")
        assessment = normalized.get("assessment.json")
        if assessment is None:
            assessment = _read(assessment_path)
        if (snapshot["fingerprint"] != manifest["source_snapshot_sha256"]
                or assessment.get("source_snapshot_sha256") != snapshot["fingerprint"]):
            raise IntegrityError("提交前 Git／來源快照異動，交易遭拒")
        seq = manifest["sequence"] + 1
        journal_path = _journal_path(root, category, seq)
        if journal_path.exists() or pending_path.exists():
            raise IntegrityError("下一筆交易日誌或預寫紀錄已存在，禁止覆寫")
        pending = {
            "schema_version": VERSION, "category": category,
            "sequence": seq, "previous": manifest["head"],
            "event": event, "source_snapshot_sha256": snapshot["fingerprint"],
            "before_hashes": before, "after_hashes": after,
            "updates": normalized, "staged_sha256": staged,
        }
        # 首先完整寫入 ahead-log；異常時保留確切更新計畫。
        _atomic(pending_path, pending)
        for relative, obj in normalized.items():
            _atomic(_artifact(root, category, relative), obj)
        if _snapshot(root) != snapshot or _hashes(root, category) != after:
            raise IntegrityError("交易寫入後來源或受控證據與預期 SHA256 不符；保留預寫紀錄")

        row = _entry({
            "schema_version": VERSION, "category": category,
            "sequence": seq, "previous": manifest["head"],
            "event": event, "source_snapshot_sha256": snapshot["fingerprint"],
            "file_hashes": after, "staged_sha256": staged,
        })
        _atomic(journal_path, row)
        _atomic(manifest_path, {
            "schema_version": VERSION, "category": category,
            "sequence": seq, "head": row["entry_hash"],
            "source_snapshot_sha256": snapshot["fingerprint"],
        })
        if staged_path is not None:
            # 真正提交後才移除 stage；若清理失敗仍保留 pending 供明確復原。
            staged_path.unlink()
        pending_path.unlink()
        return {"category": category, "sequence": seq, "head": row["entry_hash"],
                "event": event, "updated_paths": list(normalized)}
