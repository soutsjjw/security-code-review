#!/usr/bin/env python3
"""P0 前置：執行邊界能力稽核與 L3 檔案差異偵測。

沒有可信且完整的執行器工具清單時，絕不宣稱 L1/L2。
此模組只監測審查 analysis 目錄內的腳本；L3 無法觀察記憶體執行或已刪除的暫存檔。
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

from execution_boundary_events import append_violation, verify_run, fingerprint, snapshot_run_summary
from review_core import write_json_exclusive

REPORT = Path("reports/security-code-review")
SCRIPT_EXT = {".py", ".sh", ".js", ".ps1", ".cmd", ".bat", ".exe", ".dll"}

def inventory(target):
    """v1 執行器無可信的完整能力列舉 API，只能評定 L3。"""
    return {"schema_version": 1, "boundary_level": "L3",
            "trusted_inventory_available": False,
            "uncontrolled_entrypoints": "unknown",
            "assessment": "audit-only; no enforced confinement"}

def scripts(target):
    folder = Path(target).resolve() / REPORT / "analysis"
    items = {}
    if not folder.exists():
        return items
    for path in folder.rglob("*"):
        if path.is_symlink():
            # symlink 也是未受控執行入口，不可跟隨。
            if path.suffix.lower() in SCRIPT_EXT:
                items[path.relative_to(folder).as_posix()] = "symlink"
        elif path.is_file() and path.suffix.lower() in SCRIPT_EXT:
            items[path.relative_to(folder).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return items

def begin(target):
    from review_log import _paths, _load
    target = Path(target).resolve()
    active = _load(_paths(target)[1])
    if not active or active.get("status") != "running":
        raise ValueError("必須先執行 review_log.py start")
    run_id = active["run_id"]
    path = target / REPORT / "logs" / "boundary-baselines" / (run_id + ".json")
    if path.exists() or path.is_symlink():
        raise ValueError("邊界基準已存在，不可覆寫")
    path.parent.mkdir(parents=True, exist_ok=True)
    baseline = {"schema_version": 1, "run_id": run_id, "inventory": inventory(target),
                "scripts": scripts(target), "legacy_cleanup_allowed": False}
    write_json_exclusive(path, baseline, sort_keys=True)
    return baseline

def inspect(target, *, batch_id, stage="first_pass", record=False):
    from review_log import _paths, _load
    target = Path(target).resolve()
    active = _load(_paths(target)[1])
    if not active or active.get("status") != "running":
        raise ValueError("缺少有效的 running Run")
    run_id = active["run_id"]
    base_path = target / REPORT / "logs" / "boundary-baselines" / (run_id + ".json")
    if base_path.is_symlink() or not base_path.is_file():
        raise ValueError("缺少可信的本次 Run 邊界基準；先執行 --begin")
    base = json.loads(base_path.read_text("utf-8"))
    if base.get("run_id") != run_id or base.get("inventory", {}).get("boundary_level") != "L3":
        raise ValueError("邊界基準版本或等級異常")
    current = scripts(target)
    changed = {name: sha for name, sha in current.items()
               if base["scripts"].get(name) != sha}
    removed = sorted(set(base["scripts"]) - set(current))
    report = {"run_id": run_id, "batch_id": batch_id, "boundary_level": "L3",
              "detected_executables": len(changed), "removed_legacy_scripts": len(removed),
              "clean": not changed, "assurance": "audit-only",
              "inventory_fingerprint": fingerprint(base["inventory"])}
    if changed and record:
        existing = verify_run(target, run_id)
        known_blocked = set(existing["blocked_batches"])
        if batch_id not in known_blocked:
            # 事件中不保存來源或違規腳本正文。
            for name, sha in sorted(changed.items()):
                append_violation(target, run_id=run_id, batch_id=batch_id, stage=stage,
                                 boundary_level="L3",
                                 batch_fingerprint=fingerprint({"run_id": run_id, "batch_id": batch_id,
                                                                 "inventory": report["inventory_fingerprint"]}),
                                 severity="block", detection_method="filesystem-diff",
                                 policy_id="unauthorized-executable",
                                 artifact_sha256=sha if len(sha) == 64 else None)
    if record and batch_id in verify_run(target, run_id)["blocked_batches"]:
        report["clean"] = False
        report["pending_review"] = True
    report["summary_sha256"] = snapshot_run_summary(target, run_id)["summary_sha256"]
    return report

def require_clean(target, *, batch_id, stage="first_pass"):
    """僅 opt-in optimized 模式的正式交易入口呼叫；保守拒絕未覆核違規。"""
    report = inspect(target, batch_id=batch_id, stage=stage, record=True)
    if not report["clean"]:
        raise ValueError("P0 執行邊界：批次含未授權執行檔變更或待覆核違規，拒絕整合")
    return {"schema_version": 1, "run_id": report["run_id"],
            "batch_id": batch_id, "boundary_level": "L3",
            "inventory_sha256": report["inventory_fingerprint"],
            "summary_sha256": report["summary_sha256"]}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--target", type=Path, required=True)
    p.add_argument("--begin", action="store_true")
    p.add_argument("--inspect", action="store_true")
    p.add_argument("--batch-id", default="preflight")
    args = p.parse_args()
    if args.begin == args.inspect:
        p.error("指定 --begin 或 --inspect")
    try:
        result = begin(args.target) if args.begin else inspect(args.target, batch_id=args.batch_id)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        p.exit(2, "P0 邊界稽核失敗：" + str(exc) + "\n")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
