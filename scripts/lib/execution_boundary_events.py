#!/usr/bin/env python3
"""P4-A: 追加式邊界事件與可重放驗證；本階段僅觀測，不具授權覆核通道。"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from contextlib import contextmanager
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas/execution-boundary-event-v1.schema.json").read_text("utf-8"))
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
HEX = set("0123456789abcdef")

def canonical(value):
    """JCS-compatible restricted profile: schema permits integers, not floats."""
    def check(v):
        if type(v) is float:
            raise ValueError("事件不允許浮點數")
        if isinstance(v, dict):
            for key, item in v.items():
                if not isinstance(key, str):
                    raise ValueError("事件鍵必須為字串")
                check(item)
        elif isinstance(v, list):
            for item in v:
                check(item)
        elif isinstance(v, str):
            if any(0xD800 <= ord(ch) <= 0xDFFF for ch in v):
                raise ValueError("事件包含無效 Unicode surrogate")
    check(value)
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")

def fingerprint(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def events_dir(target, run_id):
    if not isinstance(run_id, str) or not run_id or any(x in run_id for x in "/\\."):
        raise ValueError("run_id 不合法")
    return Path(target).resolve() / "reports/security-code-review/logs/boundary-events" / run_id

def batch_path(target, run_id, batch_id):
    if not isinstance(batch_id, str) or not batch_id or len(batch_id) > 128 or any(
            c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in batch_id):
        raise ValueError("batch_id 不合法")
    return events_dir(target, run_id) / (batch_id + ".jsonl")

@contextmanager
def exclusive_lock(path):
    lock = path.with_suffix(".lock")
    if lock.is_symlink():
        raise ValueError("事件鎖不可為 symbolic link")
    for attempt in range(60):
        try:
            lock.mkdir()
            break
        except FileExistsError:
            if attempt == 59:
                raise ValueError("事件紀錄有另一寫入者或殘留鎖；須核查後處理")
            time.sleep(0.05)
    try:
        yield
    finally:
        lock.rmdir()

def _read_events(path):
    if path.is_symlink():
        raise ValueError("事件紀錄不可為 symbolic link")
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text("utf-8").splitlines() if line.strip()]

def _verify_events(rows, run_id, batch_id, *, trusted_review=None):
    prev = None
    ids = set()
    decisions = {}
    latest_review = {}
    latest_review_id = {}
    clearance = set()
    for index, event in enumerate(rows, 1):
        VALIDATOR.validate(event)
        if (event["run_id"] != run_id or event["batch_id"] != batch_id
                or event["batch_sequence"] != index or event["previous_event_sha256"] != prev):
            raise ValueError("事件序號／鏈接／Run／Batch 不一致")
        eid = event["event_id"]
        if eid in ids:
            raise ValueError("事件 UUID 重複")
        ids.add(eid)
        computed = fingerprint({k: v for k, v in event.items() if k != "event_sha256"})
        if event["event_sha256"] != computed:
            raise ValueError("事件指紋不一致")
        prev = computed
        typ = event["event_type"]
        if typ == "execution_boundary_violation":
            if event["severity"] == "block":
                decisions[eid] = ("pending_review", event)
        elif typ == "execution_boundary_review":
            origin = decisions.get(event["related_event_id"])
            if origin is None or trusted_review is None or not trusted_review(event):
                raise ValueError("覆核事件缺少可信授權證明")
            base = origin[1]
            if (event["previous_review_event_id"] != latest_review_id.get(event["related_event_id"])
                    or event["artifact_sha256"] != base["artifact_sha256"]):
                raise ValueError("覆核引用或證據版本不一致")
            decisions[event["related_event_id"]] = (event["final_ruling"], base)
            latest_review[event["related_event_id"]] = event
            latest_review_id[event["related_event_id"]] = eid
            clearance.discard(event["related_event_id"])
        elif typ == "execution_boundary_clearance":
            related = event["related_event_id"]
            review = latest_review.get(related)
            if (review is None or review["final_ruling"] != "overturned"
                    or event["related_review_event_id"] != review["event_id"]
                    or event["artifact_sha256"] != review["artifact_sha256"]
                    or event["batch_fingerprint"] != review["batch_fingerprint"]):
                raise ValueError("重新驗證與有效覆核不一致")
            clearance.add(related)
    unresolved = [status for eid, (status, _) in decisions.items()
                  if not (status == "overturned" and eid in clearance)]
    outcome = ("blocked_execution_boundary" if "upheld" in unresolved else
               "blocked_pending_review" if unresolved else "no_block_events")
    return {"event_count": len(rows), "head_event_sha256": prev, "status": outcome}

def verify_run(target, run_id, *, trusted_review=None):
    folder = events_dir(target, run_id)
    batches = []
    seen = set()
    for path in sorted(folder.glob("*.jsonl")) if folder.exists() else []:
        batch_id = path.stem
        rows = _read_events(path)
        for row in rows:
            if row.get("event_id") in seen:
                raise ValueError("跨批次 UUID 重複")
            seen.add(row.get("event_id"))
        result = _verify_events(rows, run_id, batch_id, trusted_review=trusted_review)
        batches.append({"batch_id": batch_id, **result})
    return {"schema_version": 1, "run_id": run_id, "batches": batches,
            "summary_sha256": fingerprint(batches),
            "blocked_batches": [x["batch_id"] for x in batches if x["status"].startswith("blocked")]}


def snapshot_run_summary(target, run_id):
    """單寫者保存不可變 Run 摘要；每筆可回溯至各 Batch 事件鏈頭。"""
    validated = verify_run(target, run_id)
    base = events_dir(target, run_id) / "summaries"
    base.mkdir(parents=True, exist_ok=True)
    gate = base / "summary"
    schema = json.loads((ROOT / "schemas/execution-boundary-run-summary-v1.schema.json").read_text("utf-8"))
    check = Draft202012Validator(schema, format_checker=FormatChecker())
    with exclusive_lock(gate):
        prior = sorted(base.glob("*.json"))
        previous = None
        for index, path in enumerate(prior, 1):
            obj = json.loads(path.read_text("utf-8"))
            check.validate(obj)
            if (path.name != f"{index:08d}.json"
                    or obj["summary_sequence"] != index
                    or obj["previous_summary_sha256"] != previous
                    or obj["summary_sha256"] != fingerprint({
                        k: val for k, val in obj.items() if k != "summary_sha256"
                    })):
                raise ValueError("Run 摘要歷史或鏈結異常")
            previous = obj["summary_sha256"]
        heads = [{"batch_id": b["batch_id"], "event_count": b["event_count"],
                  "head_event_sha256": b["head_event_sha256"]}
                 for b in validated["batches"] if b["event_count"]]
        if prior:
            last = json.loads(prior[-1].read_text("utf-8"))
            if last["batch_heads"] == heads:
                return last
        obj = {"schema_version": 1, "run_id": run_id,
               "summary_sequence": len(prior) + 1,
               "created_at": datetime.now(timezone.utc).isoformat(),
               "previous_summary_sha256": previous, "batch_heads": heads}
        obj["summary_sha256"] = fingerprint(obj)
        check.validate(obj)
        path = base / f"{obj['summary_sequence']:08d}.json"
        with path.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(obj, ensure_ascii=False, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        return obj


def append_violation(target, *, run_id, batch_id, stage, boundary_level, batch_fingerprint,
                     severity, detection_method, policy_id, artifact_sha256=None):
    path = batch_path(target, run_id, batch_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("事件紀錄不可為 symbolic link")
    with exclusive_lock(path):
        rows = _read_events(path)
        _verify_events(rows, run_id, batch_id)
        event = {
            "schema_version": 1, "event_id": str(uuid.uuid4()),
            "event_type": "execution_boundary_violation",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "run_id": run_id, "batch_id": batch_id, "stage": stage,
            "boundary_level": boundary_level, "batch_sequence": len(rows) + 1,
            "batch_fingerprint": batch_fingerprint,
            "previous_event_sha256": rows[-1]["event_sha256"] if rows else None,
            "severity": severity, "detection_method": detection_method,
            "policy_id": policy_id, "artifact_sha256": artifact_sha256,
            "disposition": "pending_review" if severity == "block" else "auto_warn",
            "origin": "boundary-monitor",
        }
        event["event_sha256"] = fingerprint(event)
        VALIDATOR.validate(event)
        with path.open("a", encoding="utf-8") as output:
            output.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
            output.flush()
            os.fsync(output.fileno())
    return event

def main():
    p = argparse.ArgumentParser(description="P4-A 執行邊界事件唯讀觀測")
    p.add_argument("--target", type=Path, required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--verify", action="store_true")
    args = p.parse_args()
    if not args.verify:
        p.error("v1 CLI 僅支援 --verify；覆核與事件提交不得由 Agent 自行宣稱可信")
    try:
        output = verify_run(args.target, args.run_id)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        p.exit(2, "事件驗證失敗：" + str(exc) + "\n")
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
