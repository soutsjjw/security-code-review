#!/usr/bin/env python3
"""分類審查獨立證據交易：預寫日誌、SHA256 鏈與排他鎖。

每個分類擁有獨立封存與受控提交；交易中斷保持 pending 等待明確復原。
不宣稱多檔案具備作業系統級原子性；復原只允許明確的驗證後重播。

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



def gate_errors(root: Path, category: str, *, require_seal: bool = False) -> list[str]:
    """分類審查完整性入口：全新待審查資料可未封存，既有證據不得無封存。

    報告生成／驗證須 require_seal=True；一般佇列或安全檢驗允許原始
    initialize() 產生的 pending 模板，待 stage() 才自動初始封存。
    """
    try:
        manifest = _artifact(root, category, MANIFEST)
        pending = _artifact(root, category, PENDING)
        if manifest.exists() or pending.exists():
            return errors(root, category)
        missing = f"{category}: 已有分類審查資料但缺少 Manifest（integrity-manifest.json）；禁止將未封存證據視為可信"
        if require_seal:
            return [missing]
        directory = _category_dir(root, category)
        if not directory.exists():
            return []
        # 即使 Journal 只有空目錄，也代表可能有尚未完成的封存。
        for path in (JOURNAL, STAGED, HISTORY, LOCK, *TRACKED[3:]):
            if _artifact(root, category, path).exists():
                return [missing]
        if (_artifact(root, category, "report.json").exists()
                or any(directory.glob("CodeReview_*.html"))):
            return [missing]
        assessment_path = _artifact(root, category, "assessment.json")
        project_path = _artifact(root, category, "project.json")
        snapshot_path = _artifact(root, category, "analysis/source-snapshot.json")
        if not (assessment_path.exists() or project_path.exists() or snapshot_path.exists()):
            return []
        if not all(p.is_file() for p in (assessment_path, project_path, snapshot_path)):
            return [f"{category}: 分類初始化資料不完整且缺少 Manifest；拒絕沿用"]
        # 只能允許真正尚未審查的初始模板，不能只以 execution.state=pending
        # 判斷：經改寫的 reason、evidence 或額外欄位同樣需要完整性封存。
        from partial_review import _pending_check, _category_rules
        catalog = load_catalog()
        assessment = read_category(root, category, catalog)
        pristine = [_pending_check(rule) for rule in _category_rules(catalog, category)]
        if (assessment["checks"] != pristine or assessment["findings"]
                or assessment["file_reviews"]):
            return [missing]
        return []
    except (OSError, ValueError, TypeError, KeyError, ScopeError) as exc:
        return [f"{category}: 未封存分類狀態無法安全驗證：{exc}"]

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


def _verified_chain(root: Path, category: str, manifest: dict) -> dict:
    """只核對已提交 Journal 鏈，不依賴中斷中的受控檔案內容。"""
    seq = manifest.get("sequence")
    if (manifest.get("schema_version") != VERSION or manifest.get("category") != category
            or type(seq) is not int or seq < 0
            or not isinstance(manifest.get("head"), str)
            or not _HASH.fullmatch(manifest["head"])
            or not isinstance(manifest.get("source_snapshot_sha256"), str)
            or not _HASH.fullmatch(manifest["source_snapshot_sha256"])):
        raise IntegrityError("完整性 Manifest 版本、身分、序號或 SHA256 無效")
    history: dict | None = None
    previous = None
    for n in range(seq + 1):
        path = _journal_path(root, category, n)
        if not path.is_file():
            raise IntegrityError(f"交易日誌缺少序號 {n}")
        row = _read(path)
        if not isinstance(row, dict):
            raise IntegrityError(f"交易日誌序號 {n} 內容格式無效")
        raw = {k: v for k, v in row.items() if k != "entry_hash"}
        if (row.get("entry_hash") != _entry(raw)["entry_hash"]
                or row.get("schema_version") != VERSION
                or row.get("category") != category
                or type(row.get("sequence")) is not int or row["sequence"] != n
                or row.get("previous") != previous
                or row.get("source_snapshot_sha256") != manifest["source_snapshot_sha256"]
                or not _valid_hashes(row.get("file_hashes"))):
            raise IntegrityError(f"交易日誌序號 {n} 的內容或鏈結驗證失敗")
        history = row
        previous = row["entry_hash"]
    if history is None or manifest["head"] != previous:
        raise IntegrityError("Manifest 與交易日誌鏈 head 不一致")
    return history


def _pending_details(root: Path, category: str, pending: dict,
                     manifest: dict, tip: dict) -> tuple[dict, bool]:
    if not isinstance(pending, dict):
        raise IntegrityError("待復原交易不是 JSON 物件")
    seq, updates = pending.get("sequence"), pending.get("updates")
    before, after = pending.get("before_hashes"), pending.get("after_hashes")
    stored = pending.get("staged_sha256")
    if (pending.get("schema_version") != VERSION or pending.get("category") != category
            or type(seq) is not int or seq < 1
            or not isinstance(pending.get("event"), str) or not pending["event"]
            or not isinstance(pending.get("previous"), str)
            or not isinstance(pending.get("source_snapshot_sha256"), str)
            or not _HASH.fullmatch(pending["source_snapshot_sha256"])
            or not isinstance(updates, dict) or not updates
            or not isinstance(stored, dict) or not _valid_hashes(before)
            or not _valid_hashes(after)):
        raise IntegrityError("待復原交易格式／分類身分或受控雜湊清單無效")

    normalized: dict[str, str] = {}
    for relative, value in updates.items():
        if not isinstance(relative, str) or not isinstance(value, (dict, list)):
            raise IntegrityError("交易更新須為受控 JSON 物件或陣列")
        permitted = relative in TRACKED or (
            relative.startswith(HISTORY.as_posix() + "/")
            and _HISTORY_NAME.fullmatch(relative[len(HISTORY.as_posix()) + 1:]))
        if not permitted:
            raise IntegrityError(f"復原拒絕非分類受控路徑：{relative}")
        _artifact(root, category, relative)  # 驗證 path traversal 與 symbolic link
        normalized[relative] = _sha(_json_bytes(value))
    if (not set(TRACKED) <= set(before)
            or not set(before) <= set(after)
            or set(after) != set(before) | set(updates)
            or any(after[k] != normalized.get(k, before.get(k)) for k in after)
            or any(k in before and before[k] is None and k not in updates and after[k] is not None
                   for k in after)):
        raise IntegrityError("待復原交易的前後 SHA256 與實際更新清單不一致")

    if stored:
        if (set(stored) != {STAGED.as_posix()}
                or not isinstance(stored[STAGED.as_posix()], str)
                or not _HASH.fullmatch(stored[STAGED.as_posix()])):
            raise IntegrityError("復原 staged SHA256 格式或路徑不符")
    if pending["source_snapshot_sha256"] != manifest["source_snapshot_sha256"]:
        raise IntegrityError("待復原交易的來源指紋不同於已封存來源")

    committed = seq == manifest["sequence"]
    if committed:
        prior = _read(_journal_path(root, category, seq - 1))
        if (prior.get("entry_hash") != pending["previous"]
                or prior.get("file_hashes") != before):
            raise IntegrityError("待復原交易的原始證據與上一筆 Journal 不一致")
        if (tip.get("sequence") != seq
                or tip.get("previous") != pending["previous"]
                or tip.get("file_hashes") != after or tip.get("event") != pending["event"]
                or tip.get("staged_sha256") != stored):
            raise IntegrityError("已提交日誌內容與待復原交易不一致")
    elif (seq != manifest["sequence"] + 1 or tip["entry_hash"] != pending["previous"]
          or tip["file_hashes"] != before):
        raise IntegrityError("待復原交易的上一版 SHA256 與已提交的 Journal 鏈不一致")

    row = _entry({
        "schema_version": VERSION, "category": category,
        "sequence": seq, "previous": pending["previous"], "event": pending["event"],
        "source_snapshot_sha256": pending["source_snapshot_sha256"],
        "file_hashes": after, "staged_sha256": stored,
    })
    journal_path = _journal_path(root, category, seq)
    journal_names = {f"{n:08d}.json" for n in range(manifest["sequence"] + 1)}
    if not committed and journal_path.is_file():
        if _read(journal_path) != row:
            raise IntegrityError("待復原的 Journal 已存在不同內容")
        journal_names.add(journal_path.name)
    actual = {item.name for item in _artifact(root, category, JOURNAL).iterdir()}
    if actual != journal_names:
        raise IntegrityError("Journal 目錄有缺漏、額外或未授權檔案")
    return row, committed


def recover(root: Path, category: str) -> dict[str, Any]:
    """明確復原分類交易；無 pending 時只驗證已完成狀態，具備冪等性。

    交易成功前先驗證來源、所有受控檔案只符合 before/after、
    staged SHA256 與既有 Journal。第三種內容一律拒絕，不修改任何資料。
    """
    with locked(root, category):
        manifest_path = _artifact(root, category, MANIFEST)
        pending_path = _artifact(root, category, PENDING)
        if not manifest_path.is_file():
            raise IntegrityError("分類完整性 Manifest 不存在，不允許復原")
        if not pending_path.is_file():
            if _artifact(root, category, STAGED).exists():
                raise IntegrityError("沒有需要復原的完整性交易，但仍有尚未整合的 staged 批次")
            problems = errors(root, category)
            if problems:
                raise IntegrityError("；".join(problems))
            manifest = _read(manifest_path)
            return {"category": category, "recovered": False,
                    "already_completed": True, "sequence": manifest["sequence"],
                    "head": manifest["head"]}
        manifest = _read(manifest_path)
        if not isinstance(manifest, dict):
            raise IntegrityError("分類 Manifest 內容不合法")
        tip = _verified_chain(root, category, manifest)
        pending = _read(pending_path)
        row, committed = _pending_details(root, category, pending, manifest, tip)

        source = _snapshot(root)
        if source["fingerprint"] != pending["source_snapshot_sha256"]:
            raise IntegrityError("來源或 Git Revision 已異動，禁止自動復原")
        expected_snapshot_path = _artifact(root, category, "analysis/source-snapshot.json")
        stored_snapshot = _read(expected_snapshot_path) if expected_snapshot_path.is_file() else None
        if (not isinstance(stored_snapshot, dict)
                or stored_snapshot.get("fingerprint") != source["fingerprint"]
                or stored_snapshot != source):
            raise IntegrityError("分類來源快照遭修改，禁止自動復原")
        staged = pending["staged_sha256"]
        staged_path = _artifact(root, category, STAGED)
        if staged:
            expected_sha = staged[STAGED.as_posix()]
            current_sha = _file_hash(staged_path)
            if current_sha != expected_sha and not (committed and current_sha is None):
                raise IntegrityError("分類 staged 批次已變更或在提交前消失，禁止復原")
        elif staged_path.exists():
            raise IntegrityError("非 staged 交易出現未授權 staged 暫存資料")

        before, after = pending["before_hashes"], pending["after_hashes"]
        live = _hashes(root, category)
        if not set(live) <= set(after) or set(after) - set(live) - set(pending["updates"]):
            raise IntegrityError("復原前受控檔案清單遭新增或刪除（包含修訂歷史）")
        for relative in set(after) - set(live):
            # 只允許交易預期新增、且目前尚未落盤的修訂歷史檔案。
            if relative in before or not relative.startswith(HISTORY.as_posix() + "/"):
                raise IntegrityError("復原交易存在非預期的檔案清單變化")
            live[relative] = None
        for relative, actual in live.items():
            permitted = {after[relative]} if committed else {before.get(relative), after[relative]}
            if actual not in permitted:
                raise IntegrityError(f"{relative}: 受控證據遭第三種內容修改，拒絕復原")
            if relative not in pending["updates"] and actual != before[relative]:
                raise IntegrityError(f"{relative}: 未列入交易的證據被變更，拒絕復原")
        if committed:
            if live != after:
                raise IntegrityError("Manifest 已提交，但受控檔案不符合已封存 SHA256")
        else:
            # 所有檔案及 staged 指紋已完成預檢才允許補寫任何目標。
            for relative, value in pending["updates"].items():
                if live[relative] != after[relative]:
                    _atomic(_artifact(root, category, relative), value)
            if _snapshot(root) != source or _hashes(root, category) != after:
                raise IntegrityError("復原寫入後來源或證據 SHA256 不一致；保留 pending")

            journal = _journal_path(root, category, pending["sequence"])
            if journal.is_file():
                if _read(journal) != row:
                    raise IntegrityError("Journal 中已有不同交易，禁止覆寫")
            else:
                _atomic(journal, row)
            _atomic(manifest_path, {
                "schema_version": VERSION, "category": category,
                "sequence": pending["sequence"], "head": row["entry_hash"],
                "source_snapshot_sha256": source["fingerprint"],
            })

        # 當 Manifest 已提交且檔案全部一致才清理 staged/pending。
        if staged and staged_path.is_file():
            staged_path.unlink()
        pending_path.unlink()
        problems = errors(root, category)
        if problems:
            raise IntegrityError("復原完成後完整性驗證失敗：" + "；".join(problems))
        return {"category": category, "recovered": True,
                "already_completed": False, "sequence": pending["sequence"],
                "head": row["entry_hash"], "event": pending["event"],
                "updated_paths": list(pending["updates"])}
