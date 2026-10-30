#!/usr/bin/env python3
"""P5 分類報告的單次交易發布與失敗復原。

跨多個檔案沒有 OS 級原子交易：本模組在同一程序可捕獲失敗時
還原全部既有輸出；程序崩潰或斷電留下的 staging/backup 不宣稱自動復原。
"""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import shutil
import tempfile
from typing import Callable, Iterator, Sequence
from review_scope import PARTIAL_ROOT


class PublicationError(ValueError):
    """輸出不一致、同時發布或發布中斷。"""


def _replace(source: Path, destination: Path) -> None:
    os.replace(source, destination)


def _temp_path(directory: Path, suffix: str) -> Path:
    fd, filename = tempfile.mkstemp(prefix=".review-p5-", suffix=suffix, dir=directory)
    os.close(fd)
    return Path(filename)


def _write_staged(path: Path, body: str) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())


@contextmanager
def _publish_lock(root: Path) -> Iterator[None]:
    # 僅允許根目錄下固定的 partial 位置，不接受來自 CLI 的路徑。

    base = root.resolve()
    directory = base / PARTIAL_ROOT
    current = directory
    while current != base:
        if current.is_symlink():
            raise PublicationError("分類報告資料夾不能是 symbolic link")
        current = current.parent
    if not directory.resolve().is_relative_to(base):
        raise PublicationError("分類報告資料夾不得指向工作樹外部")
    directory.mkdir(parents=True, exist_ok=True)
    lock = directory / ".publish.lock"
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise PublicationError("已有分類報告發布工作，拒絕同時寫入；請核對 .publish.lock") from exc
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(f"pid={os.getpid()}\n")
        yield
    finally:
        lock.unlink(missing_ok=True)


def publish(root: Path, outputs: Sequence[tuple[Path, str]], *,
            validate: Callable[[], list[str]],
            verify_saved: Callable[[], list[str]]) -> None:
    """預備全部檔案並複製備份，驗證後提交；任何受控失敗都保留舊報告。

    只接受分類目錄的 JSON/HTML，不能把正式 70 項報告當成目標。
    """

    root = root.resolve()
    destinations = [path for path, _ in outputs]
    if not destinations or len(destinations) != len(set(destinations)):
        raise PublicationError("分類報告目標路徑空白或重複")
    partial_base = (root / PARTIAL_ROOT).resolve()
    for path in destinations:
        resolved = path.resolve()
        if (path.is_symlink() or path.parent.is_symlink()
                or not resolved.is_relative_to(partial_base)
                or resolved == partial_base or path.name not in {"report.json"}
                and not (path.name.startswith("CodeReview_") and path.suffix == ".html")):
            raise PublicationError(f"禁止覆寫非分類報告：{path}")
        # 不許寫入 _shared、非 AC～SI 或巢狀分類不明目錄。
        relative = resolved.relative_to(partial_base).parts
        from review_scope import CATEGORIES
        if len(relative) != 2 or relative[0] not in CATEGORIES:
            raise PublicationError(f"非獨立分類資料夾：{path}")
    prepared: list[tuple[Path, Path, Path | None]] = []
    committed: list[tuple[Path, Path | None]] = []
    rollback_errors: list[str] = []
    with _publish_lock(root):
        try:
            for destination, content in outputs:
                # 重驗父目錄及 symlink，避免等待發布鎖期間被換掉。
                from partial_review_store import _artifact
                category = destination.relative_to(root / PARTIAL_ROOT).parts[0]
                guarded = _artifact(root, category, destination.name)
                if guarded != destination or destination.is_symlink():
                    raise PublicationError("分類輸出路徑在驗證後遭到更改")
                destination.parent.mkdir(parents=True, exist_ok=True)
                stage = _temp_path(destination.parent, ".stage")
                backup: Path | None = None
                try:
                    _write_staged(stage, content)
                    if destination.exists():
                        backup = _temp_path(destination.parent, ".backup")
                        shutil.copy2(destination, backup)
                except BaseException:
                    stage.unlink(missing_ok=True)
                    if backup is not None:
                        backup.unlink(missing_ok=True)
                    raise
                prepared.append((destination, stage, backup))
            issues = validate()
            if issues:
                raise PublicationError("提交前審查來源或報告證據驗證失敗：" + "；".join(issues[:8]))
            for destination, stage, backup in prepared:
                _replace(stage, destination)
                committed.append((destination, backup))
            # 可能在提交期間發生來源／評估資料異動：提交後再次驗證，
            # 若不一致則回滾本次所有分類的報告。
            issues = [*validate(), *verify_saved()]
            if issues:
                raise PublicationError("提交後驗證失敗，還原舊報告：" + "；".join(issues[:8]))
        except BaseException:
            for destination, backup in reversed(committed):
                try:
                    if backup is not None and backup.exists():
                        _replace(backup, destination)
                    else:
                        destination.unlink(missing_ok=True)
                except OSError as exc:
                    # 不能拋棄尚未還原的舊版備份，交由人工復原。
                    rollback_errors.append(f"{destination}: {exc}")
            if rollback_errors:
                raise PublicationError("發布失敗且舊報告未能全數復原；"
                                       "請保留分類目錄中的 .backup 檔：" + "；".join(rollback_errors))
            raise
        finally:
            for _, stage, backup in prepared:
                stage.unlink(missing_ok=True)
                if backup is not None and not rollback_errors:
                    backup.unlink(missing_ok=True)
