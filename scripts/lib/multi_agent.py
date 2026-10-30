#!/usr/bin/env python3
"""Main-agent-only multi-agent ledger CLI. Does not spawn agents or modify assessment.

實作分於 multi_agent_ledger（狀態）、multi_agent_planning（試跑與計畫）、multi_agent_workers（分片生命週期）；
此處保留 CLI 與既有公開名稱。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from multi_agent_ledger import (ANALYSIS, HIGH_RISK, INDEX, LEDGER, PROBE, REPORT, RETRY_LIMIT, SNAPSHOT,
                               _active, _fingerprint, _read, _snapshot, _write)
from multi_agent_planning import (begin_integration, commit_integration, plan, probe_template, record_probe,
                                 renew_probe)
from multi_agent_workers import (accept, accept_followup, accept_followup_stdin, accept_stdin, blind_tasks,
                                claim, claim_batch, fail, followup, renew_budget, resolve_main, summary)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=Path.cwd())
    mode = parser.add_mutually_exclusive_group(required=True)
    for name in ("probe-template", "record-probe", "renew-probe", "plan", "begin-integration", "commit-integration", "resolve-main", "next", "claim", "claim-batch", "fail", "followup", "accept-followup", "accept-followup-stdin", "renew-budget", "accept", "accept-stdin",
                 "status", "blind-tasks"):
        mode.add_argument("--" + name, action="store_true")
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--task-id")
    parser.add_argument("--agent-id")
    parser.add_argument("--assignments", type=Path)
    parser.add_argument("--result", type=Path)
    parser.add_argument("--max-agents", type=int, default=3)
    parser.add_argument("--replan", action="store_true")
    parser.add_argument("--budget-tokens", type=int, default=96000)
    parser.add_argument("--task-tokens", type=int, default=12000)
    args = parser.parse_args()
    root = args.target.resolve()
    try:
        if args.probe_template:
            answer = probe_template()
        elif args.record_probe:
            if args.evidence is None:
                raise ValueError("--record-probe 必須指定 --evidence")
            answer = record_probe(root, _read(args.evidence))
        elif args.renew_probe:
            if args.evidence is None:
                raise ValueError("--renew-probe 需提供新試跑紀錄 --evidence")
            answer = renew_probe(root, _read(args.evidence))
        elif args.plan:
            state = plan(root, max_agents=args.max_agents,
                         budget_tokens=args.budget_tokens, task_tokens=args.task_tokens,
                         replan=args.replan)
            answer = {"multi_agent_enabled": state["multi_agent_enabled"],
                      "workers": state["workers"],
                      "fallback_reason": state["fallback_reason"],
                      "task_count": len(state["tasks"]), "formal_review_completed": False}
        elif args.resolve_main:
            if not args.task_id or args.evidence is None:
                raise ValueError("--resolve-main 需要 --task-id 與 --evidence")
            answer = resolve_main(root, args.task_id, args.evidence)
        elif args.begin_integration:
            answer = begin_integration(root)
        elif args.commit_integration:
            answer = commit_integration(root)
        elif args.next:
            state, _ = _active(root)
            answer = {"tasks": [row["task"] for row in state["tasks"].values()
                                if row["status"] in ("pending", "failed")
                                and row["attempts"] < RETRY_LIMIT],
                      "running": {key: {"claimed_at": row.get("claimed_at"),
                                         "agent_instance_id": row.get("agent_instance_id"),
                                         "status": row["status"]}
                                  for key, row in state["tasks"].items()
                                  if row["status"] in ("running", "followup_running")},
                      "unresolved_followups": [key for key, row in state["tasks"].items()
                                               if row["status"] in ("needs_followup", "needs_main")],
                      "formal_review_completed": False}
        elif args.claim_batch:
            if args.assignments is None or args.assignments.is_symlink():
                raise ValueError("--claim-batch 必須指定受控 --assignments JSON 路徑")
            payload = json.loads(args.assignments.read_text(encoding="utf-8"))
            answer = claim_batch(root, payload)
        elif args.claim:
            if not args.task_id:
                raise ValueError("--claim 必須指定 --task-id")
            answer = claim(root, args.task_id, agent_id=args.agent_id)
        elif args.fail:
            if not args.task_id:
                raise ValueError("--fail 必須指定 --task-id")
            answer = fail(root, args.task_id)
        elif args.followup:
            if not args.task_id or not args.agent_id:
                raise ValueError("--followup 必須指定 --task-id 與 --agent-id")
            answer = followup(root, args.task_id, agent_id=args.agent_id)
        elif args.accept_followup_stdin:
            answer = accept_followup_stdin(root, sys.stdin.read(2_000_001))
        elif args.accept_followup:
            if args.result is None:
                raise ValueError("--accept-followup 必須指定 --result")
            answer = accept_followup(root, args.result)
        elif args.renew_budget:
            answer = renew_budget(root)
        elif args.accept_stdin:
            answer = accept_stdin(root, sys.stdin.read(2_000_001))
        elif args.accept:
            if args.result is None:
                raise ValueError("--accept 必須指定 --result")
            answer = accept(root, args.result)
        elif args.status:
            answer = summary(root)
        else:
            answer = blind_tasks(root)
        print(json.dumps(answer, ensure_ascii=False, separators=(",", ":")))
        return 0 if not (args.accept and not answer.get("accepted")) else 2
    except (OSError, ValueError, KeyError, TypeError, UnicodeError,
            json.JSONDecodeError) as exc:
        print("ERROR: 多代理守門拒絕操作：" + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
