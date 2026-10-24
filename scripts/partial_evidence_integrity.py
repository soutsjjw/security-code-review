#!/usr/bin/env python3
"""分類審查的獨立證據完整性基礎（R1；尚未接入 stage/integrate）。

每個分類具有自己的初始封存、SHA256 日誌鏈及排他寫入鎖。
R2/R3 才會實作預寫交易與復原，R1 不宣稱多檔案原子提交。

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
        other_evidence = any(paths[k].is_file() for k in TRACKED[3:])
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
