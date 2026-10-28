#!/usr/bin/env python3
"""受控證據備份／復原與無可信備份時的新審查起點；絕不合成安全結論。"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import evidence_integrity as ledger

REPORT = Path("reports/security-code-review")
ARCHIVES = Path("reports/security-code-review-archives")


def plan(target: Path) -> dict:
    target = target.resolve()
    report = target / REPORT
    issues = ledger.errors(target)
    status = ledger.backup_status(target)
    manifest = ledger._read(target / ledger.MANIFEST, {})
    record = None
    if isinstance(manifest, dict) and type(manifest.get("sequence")) is int:
        record = ledger._read(ledger._entry_path(target, manifest["sequence"]))
    expected = (record or {}).get("file_hashes") if isinstance(record, dict) else None
    differences = []
    restorable = bool(expected) and not ledger.errors(
        target, verify_files=False, verify_backups=False)
    replace_required = False
    if isinstance(expected, dict):
        for name, sha in expected.items():
            current = ledger._path(target, name)
            if ledger._hash_file(current) == sha:
                continue
            differences.append(name)
            if current.exists():
                replace_required = True
            if not sha:
                restorable = False
                continue
            try:
                ledger._backup_bytes(target, sha)
            except ValueError:
                restorable = False
    else:
        restorable = False
    assessment = ledger._read(report / "assessment.json", {})
    findings = assessment.get("findings", []) if isinstance(assessment, dict) else []
    return {
        "integrity_errors": issues,
        "backup_status": status,
        "mismatched_paths": differences,
        "can_restore_from_backup": bool(differences and restorable),
        "restore_requires_damaged_replacement": replace_required,
        "preserved_finding_count": len(findings) if isinstance(findings, list) else 0,
        "next_action": (
            "restore" if differences and restorable else
            "checkpoint" if not issues and not status.get("ready") else
            "archive-and-recheck" if issues else
            "continue-review"
        ),
    }


def archive_for_recheck(target: Path, *, acknowledged: bool = False) -> dict:
    """將整個不一致審查搬到獨立封存，再以 pending 起點重新取證。

    只保存既有 Findings 作為『未重新驗證的線索』；絕不自動導入正式結果。
    """
    target = target.resolve()
    if not acknowledged:
        raise ValueError("須明確指定 --acknowledge-evidence-loss 才能開始新審查")
    if (target / ledger.PENDING).exists():
        raise ValueError("尚有待復原交易，禁止封存；先人工核對 --recover-integrity")
    report = target / REPORT
    if not report.is_dir() or report.is_symlink():
        raise ValueError("找不到可封存的正式審查目錄，或目錄為 symbolic link")
    diagnosis = plan(target)
    if not diagnosis["integrity_errors"]:
        raise ValueError("完整性鏈有效，不允許用災難復原重啟審查")
    if diagnosis["can_restore_from_backup"]:
        raise ValueError("可信備份仍可恢復受控檔案，請優先執行 --restore")
    archive_root = target / ARCHIVES
    if archive_root.is_symlink():
        raise ValueError("歷史封存目錄不可為 symbolic link")
    archive_root.mkdir(parents=True, exist_ok=True)
    tag = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:12]
    archived = archive_root / tag
    assessment = ledger._read(report / "assessment.json", {})
    findings = assessment.get("findings", []) if isinstance(assessment, dict) else []
    if not isinstance(findings, list):
        raise ValueError("既有 Findings 格式錯誤，須人工保存後再處理")
    # rename 位於同一受測專案 reports 目錄下；既有 Manifest／Journal 保留原樣。
    report.rename(archived)
    try:
        (report / "analysis").mkdir(parents=True, exist_ok=False)
        marker = {
            "schema_version": 1,
            "status": "unverified-prior-evidence",
            "previous_review_archive": archived.relative_to(target).as_posix(),
            "previous_integrity_errors": diagnosis["integrity_errors"],
            "previous_manifest": ledger._read(archived / "analysis/integrity-manifest.json"),
            "findings": findings,
            "instruction": "僅作重新取證線索，不能自動宣稱已確認或匯入 assessment",
        }
        (report / "analysis/prior-findings-unverified.json").write_text(
            json.dumps(marker, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except Exception:
        # 只在新審查尚未建立任何正式資料時安全地回退歸檔動作。
        import shutil
        shutil.rmtree(report, ignore_errors=True)
        archived.rename(report)
        raise
    return {
        "archived_at": archived.as_posix(), "retained_finding_count": len(findings),
        "next_action": "review_log.py start --new-review; analysis_prepare.py; review_queue.py --init; 全部 70 項及來源重新取證",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="完整性備份驗證、可信復原及隔離的新審查起點")
    parser.add_argument("--target", required=True, type=Path)
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--plan", action="store_true", help="唯讀列出缺失、可恢復檔案與 Finding 數量")
    actions.add_argument("--checkpoint", action="store_true", help="正式證據完整時，為舊版建立 SHA256 備份檢查點")
    actions.add_argument("--restore", action="store_true", help="僅從可信內容備份還原與最新 Journal 相符的資料")
    actions.add_argument("--archive-for-recheck", action="store_true", help="沒有可信備份時隔離舊報告並開始全新取證")
    parser.add_argument("--allow-damaged-replacement", action="store_true",
                        help="允許還原現存但 SHA256 不符的受控檔案；限 --restore")
    parser.add_argument("--acknowledge-evidence-loss", action="store_true",
                        help="確認已無可信備份且接受重新取證；限 --archive-for-recheck")
    args = parser.parse_args(argv)
    if args.allow_damaged_replacement and not args.restore:
        parser.error("--allow-damaged-replacement 只能搭配 --restore")
    if args.acknowledge_evidence_loss and not args.archive_for_recheck:
        parser.error("--acknowledge-evidence-loss 只能搭配 --archive-for-recheck")
    try:
        if args.plan:
            outcome = plan(args.target)
        elif args.checkpoint:
            outcome = ledger.repair_backups(args.target)
        elif args.restore:
            outcome = ledger.restore_backups(args.target, allow_replace=args.allow_damaged_replacement)
        else:
            outcome = archive_for_recheck(args.target, acknowledged=args.acknowledge_evidence_loss)
        print(json.dumps(outcome, ensure_ascii=False, indent=2))
        return 0
    except (ValueError, OSError, TypeError, KeyError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
