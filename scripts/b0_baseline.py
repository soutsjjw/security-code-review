#!/usr/bin/env python3
"""B0: summarize existing review logs without inferring missing metrics."""
import argparse
import json
import statistics
from pathlib import Path

def observation(latest, label, commit=None, *, environment_fingerprint=None,
                ruleset_version=None, dataset_sha256=None, executor=None):
    if not isinstance(latest.get("run_id"), str):
        raise ValueError("missing run_id")
    result = {"schema_version": 1, "kind": "b0-observation", "run_id": latest["run_id"],
              "status": latest.get("status"), "commit": commit, "label": label,
              "environment_fingerprint": environment_fingerprint,
              "ruleset_version": ruleset_version, "dataset_sha256": dataset_sha256,
              "executor": executor,
              "comparable": latest.get("status") == "completed" and all(
                  (commit, environment_fingerprint, ruleset_version, dataset_sha256, executor)),
              "metrics": {}}
    data = latest.get("progress") or {}
    data_seconds = latest.get("phase_wall_seconds") or {}
    operations = latest.get("command_seconds") or {}
    values = {"commands": latest.get("commands"),
              "recorded_wall_seconds": sum(data_seconds.values()) if data_seconds else None,
              "command_seconds": sum(operations.values()) if operations else None,
              "completed_rules": data.get("completed_rules"),
              "reviewed_files": data.get("reviewed_files"),
              "second_pass_rules": data.get("second_pass_rules"),
              "input_tokens": (latest.get("token_usage") or {}).get("input_tokens"),
              "output_tokens": (latest.get("token_usage") or {}).get("output_tokens"),
              "agent_seconds": None, "blockers": None}
    for name, value in values.items():
        if name.endswith("_tokens") and value == 0:
            value = None
        measured = type(value) in (int, float) and value >= 0
        result["metrics"][name] = {"source": "measured" if measured else "unavailable",
                                    "value": value if measured else None}
    return result

def summary(observations):
    eligible = [o for o in observations if o.get("comparable") is True]
    names = sorted({n for o in eligible for n in o["metrics"]})
    result = {}
    for name in names:
        measurements = [o["metrics"][name]["value"] for o in eligible
                        if o["metrics"][name]["source"] == "measured"]
        result[name] = ({"source": "measured", "median": statistics.median(measurements),
                         "min": min(measurements), "max": max(measurements),
                         "count": len(measurements)} if measurements else
                        {"source": "unavailable", "count": 0})
    return {"schema_version": 1, "kind": "b0-aggregate", "runs": len(eligible),
            "metrics": result, "warning": "fewer than 3 runs is not a stable baseline"}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--latest", type=Path)
    p.add_argument("--commit")
    p.add_argument("--environment-fingerprint")
    p.add_argument("--ruleset-version")
    p.add_argument("--dataset-sha256")
    p.add_argument("--executor")
    p.add_argument("--aggregate", nargs="+", type=Path)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    if bool(args.latest) == bool(args.aggregate):
        p.error("choose --latest or --aggregate")
    if args.latest:
        obj = observation(json.loads(args.latest.read_text("utf-8")), str(args.latest), args.commit,
                          environment_fingerprint=args.environment_fingerprint,
                          ruleset_version=args.ruleset_version,
                          dataset_sha256=args.dataset_sha256, executor=args.executor)
    else:
        obj = summary([json.loads(f.read_text("utf-8")) for f in args.aggregate])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", "utf-8")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
