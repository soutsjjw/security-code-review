#!/usr/bin/env python3
"""Wave work contracts and defensive sample receipts.

Only the host's real agent tools can execute a work contract; Python never
pretends to create, isolate or authenticate a model executor.
"""
from __future__ import annotations
import re
from pathlib import Path

from review_core import canonical_digest as digest

ALLOWED_INDEPENDENCE = ("L0", "L1", "L2")
SHA = re.compile(r"^[0-9a-f]{64}$")


def work_contract(target: Path, state: dict, *, second_pass: dict | None = None) -> dict:
    """An executable-by-host work packet with exact scope and a fallback.

    Provider identity and actual permission probe are intentionally not
    inferred from a string passed by the user.
    """
    if state.get("phase") == "sample":
        return {"ready": False, "phase": "sample",
                "reason": "第一輪修訂完成，須先固定並實際完成風險抽樣"}
    second = state.get("phase") == "second_pass"
    if second:
        if not isinstance(second_pass, dict) or not second_pass.get("ready"):
            raise ValueError("第二輪正式工作清單無效")
        rules = [t["rule_id"] for t in second_pass.get("rule_tasks", [])]
        paths = [t["path"] for t in second_pass.get("sample_tasks", [])]
        unit = {"rule_ids": rules, "sample_paths": paths,
                "source_paths": second_pass.get("targeted_paths", [])}
        if not rules and not paths:
            return {"ready": False, "phase": "second_pass",
                    "reason": "第二輪沒有待處理工作，請檢查正式結案守門"}
    else:
        batch = next((b for b in state["batches"] if b["batch_id"] not in
                      set(state["completed_batches"]) and
                      set(b["depends_on_batch_ids"]) <= set(state["completed_batches"])), None)
        if batch is None:
            return {"ready": False, "phase": "first_pass",
                    "reason": "第一輪沒有依賴已滿足的待辦批次"}
        unit = {"batch_id": batch["batch_id"], "rule_ids": batch["rule_ids"],
                "task_ids": batch["task_ids"],
                "blocker_details": [item for task in state["tasks"]
                                    if task["task_id"] in batch["task_ids"]
                                    for item in task["blocker_details"]]}
    unit["source_snapshot_sha256"] = state["last_evidence"]["source_snapshot_sha256"]
    unit["assessment_sha256"] = state["last_evidence"]["assessment_sha256"]
    return {
        "schema_version": 1, "phase": state["phase"], "ready": True,
        "task_digest": digest(unit), "task": unit,
        "dispatch": "main-agent-must-invoke-actual-native-agent-tool",
        "agent_capability": "not-verified-by-this-script",
        "fallback": "single-main-agent-actual-source-review",
        "worker_permissions": "enforced-read-only-or-no-worker",
        "instruction": ("主代理實際讀取來源、查核控制及繞過路徑；原生子代理只可提供候選。"
                        "若沒有可信身分、唯讀試跑與真實完成回覆，降級主代理獨立逐項查證。"
                        "最後由主代理產生符合既有 Schema 的 payload，經正式 stage/integrate 保存；"
                        "不得以工作封包或候選結果取代真實證據。"),
    }


def sample_chain_append(chain: dict | None, record: dict, *,
                        expected_manifest_sha256: str | None) -> dict:
    """A detectable local hash chain, explicitly NOT a signed official Journal."""
    if not isinstance(expected_manifest_sha256, str) or not SHA.fullmatch(expected_manifest_sha256):
        raise ValueError("抽樣收據必須綁定已驗證的正式 Manifest SHA256")
    if chain is None:
        chain = {"schema_version": 1, "base_manifest_sha256": expected_manifest_sha256,
                 "entries": [], "head": None}
    if chain.get("schema_version") != 1 or not isinstance(chain.get("entries"), list):
        raise ValueError("抽樣鏈版本或格式不明")
    verify_sample_chain(chain)
    if chain["base_manifest_sha256"] != expected_manifest_sha256:
        raise ValueError("抽樣鏈固定時的 Manifest 已變更，需調查後重新核對")
    entry = {"sequence": len(chain["entries"]), "previous": chain["head"],
             "rule_id": record["rule_id"], "receipt_sha256": digest(record),
             "manifest_sha256": expected_manifest_sha256}
    entry["entry_hash"] = digest(entry)
    return {**chain, "entries": [*chain["entries"], entry], "head": entry["entry_hash"]}


def verify_sample_chain(chain: dict) -> None:
    if chain.get("schema_version") != 1 or not isinstance(chain.get("entries"), list):
        raise ValueError("抽樣鏈格式無效")
    previous = None
    for number, entry in enumerate(chain["entries"]):
        body = {k: v for k, v in entry.items() if k != "entry_hash"}
        if (entry.get("sequence") != number or entry.get("previous") != previous
                or entry.get("entry_hash") != digest(body)
                or entry.get("manifest_sha256") != chain.get("base_manifest_sha256")):
            raise ValueError("抽樣鏈遭修改或順序不一致")
        previous = entry["entry_hash"]
    if previous != chain.get("head"):
        raise ValueError("抽樣鏈 head 不一致")


def independence_metadata(*, external_probe: dict | None = None) -> dict:
    """Never infer verified independence from an untrusted self-report."""
    return {"assurance_level": "L0", "independent": False,
            "independent_agent_verified": False,
            "reason": ("未取得可由原生執行器驗證的獨立 Agent ID／隔離證明；"
                       "本協調器不得憑自述升級為 L1／L2"),
            "probe_claim_present": external_probe is not None,
            "source": "review-waves-coordinator"}
