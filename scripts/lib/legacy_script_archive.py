#!/usr/bin/env python3
"""P0 舊版臨時腳本封存：保守依賴判定、只複製、絕不執行／刪除。"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path

from execution_boundary import scripts

REPORT = Path("reports/security-code-review")

def plan(target):
    records = scripts(target)
    return {"schema_version": 1, "kind": "legacy-script-archive-plan",
            "dependency_status": "unknown",
            "allow_cleanup": False,
            "scripts": [{"path": name, "sha256": value,
                         "may_have_indirect_dependencies": True}
                        for name, value in sorted(records.items())]}

def archive(target):
    from evidence_integrity import commit, errors as integrity_errors
    target = Path(target).resolve()
    issues = integrity_errors(target)
    if issues:
        raise ValueError("封存前完整性未通過：" + "；".join(issues))
    p = plan(target)
    archive_root = target / REPORT / "archive/legacy-scripts"
    source_root = target / REPORT / "analysis"
    for row in p["scripts"]:
        sha = row["sha256"]
        if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
            raise ValueError("僅能封存無符號連結的實體腳本，依賴不明者保留原檔")
        source = source_root / row["path"]
        if not source.is_file() or source.is_symlink():
            raise ValueError("封存來源不可為 symbolic link")
        raw = source.read_bytes()
        if hashlib.sha256(raw).hexdigest() != sha:
            raise ValueError("封存來源版本已改變")
        archive_root.mkdir(parents=True, exist_ok=True)
        destination = archive_root / sha
        if destination.is_symlink():
            raise ValueError("封存目的地不可為 symbolic link")
        if destination.exists():
            if hashlib.sha256(destination.read_bytes()).hexdigest() != sha:
                raise ValueError("同指紋封存內容已遭修改")
        else:
            with destination.open("xb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        row["archive_sha256"] = sha
    manifest = json.dumps(p, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":")).encode("utf-8")
    manifest_sha = hashlib.sha256(manifest).hexdigest()
    folder = target / REPORT / "archive/legacy-manifests"
    folder.mkdir(parents=True, exist_ok=True)
    dest = folder / (manifest_sha + ".json")
    if not dest.exists():
        with dest.open("xb") as stream:
            stream.write(manifest + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
    elif dest.read_bytes().rstrip(b"\n") != manifest:
        raise ValueError("封存清單指紋不一致")
    receipt = {"schema_version": 1, "manifest_sha256": manifest_sha,
               "script_count": len(p["scripts"]), "allow_cleanup": False}
    commit(target, {}, event="legacy-script-archive", archive_attestation=receipt)
    return receipt

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, type=Path)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--plan", action="store_true")
    group.add_argument("--archive", action="store_true")
    args = parser.parse_args()
    try:
        outcome = plan(args.target) if args.plan else archive(args.target)
    except (OSError, ValueError) as exc:
        parser.exit(2, "封存失敗：" + str(exc) + "\n")
    print(json.dumps(outcome, ensure_ascii=False, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
