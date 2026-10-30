#!/usr/bin/env python3
"""Wave 0–4 fail-closed coordinator for REAL, agent-supplied security review.

The coordinator never writes source, fabricates evidence, decides Pass/Fail, or
changes the authoritative assessment directly. The only formal write path is
review_safety.stage/integrate and begin_second_pass; all other state is an
untrusted operational checkpoint under logs/, not a signed Journal.
"""
from __future__ import annotations

import argparse
from datetime import date
import hashlib
import json
import math
from pathlib import Path

from review_core import canonical_digest as _digest, file_sha256 as _file_sha
import review_waves_state as ws
from review_snapshot import high_tier_rules
from review_waves_abort import abort_uncommitted, inspect_uncommitted
from review_waves_lifecycle import agent_next, finalize, reconcile
from review_waves_contracts import sample_chain_append, verify_sample_chain
from rule_repair_tasks import compare_rule_repair_diagnostics
from source_reader import digest_matches

SNAPSHOT = ws.REPORT / "analysis/source-snapshot.json"


def _sample_policy(changed: list[str], mandatory: list[str], initial_signature: str,
                   assessment: dict) -> dict:
    """Seeded risk-stratified selection; force all material control changes."""
    rules = sorted(set(changed))
    force = sorted(set(mandatory) & set(rules))
    minimum = min(len(rules), max(5, math.ceil(len(rules) * 0.1))) if rules else 0
    checks = {c.get("id"): c for c in assessment.get("checks", []) if isinstance(c, dict)}

    high_tier = high_tier_rules()

    def tier(rule_id: str) -> str:
        # 規則審查強度以 rules.json 的 review_tier 為準；fail／review 結論另外提高分層。
        check = checks.get(rule_id, {})
        if check.get("status") == "fail" or rule_id in high_tier:
            return "high"
        if check.get("status") == "review":
            return "medium"
        return "low"

    strata = {name: [rid for rid in rules if tier(rid) == name]
              for name in ("high", "medium", "low")}
    def tie(rid: str) -> str:
        return hashlib.sha256((initial_signature + ":" + rid).encode()).hexdigest()

    selected = set(force)
    # Coverage across nonempty strata, even when mandatory checks consume the
    # minimum budget. This can legitimately exceed the nominal 10%.
    for values in strata.values():
        if values and not selected.intersection(values):
            selected.add(min(values, key=tie))
    for name in ("high", "medium", "low"):
        if len(selected) >= minimum:
            break
        for rid in sorted(strata[name], key=tie):
            if len(selected) >= minimum:
                break
            selected.add(rid)
    return {"rule_count": len(rules), "minimum_sample_count": minimum,
            "mandatory_rules": force, "selected_rules": sorted(selected),
            "strata_population": {name: len(rows) for name, rows in strata.items()},
            "strata_selected": {name: len(selected.intersection(rows))
                                for name, rows in strata.items()},
            "selection": "mandatory-plus-seeded-stratified-risk",
            "seed_binding": initial_signature,
            "limitations": "僅產生具代表性工作清單；真實人工核查與代理獨立性需另行驗證"}


def _result(state: dict, *, include_plan: bool = False) -> dict:
    pending = ws._next_batch(state)
    return {"schema_version": ws.VERSION, "phase": state["phase"],
            "paused": state.get("paused", False),
            "pause_reasons": state.get("pause_reasons", []),
            "initial_blocker_signature": state["initial_signature"],
            "completed_batch_count": len(state["completed_batches"]),
            "batch_count": len(state["batches"]),
            "next_batch": pending,
            "changed_rule_count": len(state["changed_rules"]),
            "sampled_rule_count": len(state.get("sample_records", {})),
            "note": "只有正式 stage/integrate 可修改證據；沒有 Agent 真實查核不會自動清除 blocker。",
            **({"tasks": state["tasks"], "sample_policy": state.get("sample_policy")}
               if include_plan else {})}


def start(target: Path) -> dict:
    """Wave 0 preflight + Wave 1 freeze a read-only execution schedule."""
    if (target / ws.STATE).exists():
        raise ValueError("已有 checkpoint；使用 --next 續跑，禁止重新初始化覆蓋")
    ws._stage_clean(target)
    evidence = ws._evidence_state(target)
    if not isinstance(evidence.get("manifest_sha256"), str) or len(evidence["manifest_sha256"]) != 64:
        raise ValueError("Wave 0 必須先建立並驗證正式 Manifest／Journal；不得使用未封存來源")
    diag, plan = ws._diagnose_and_plan(target)
    if not plan["task_coverage"]["valid"]:
        raise ValueError("權威阻塞無法完整排程，禁止啟動：" +
                         json.dumps(plan["task_coverage"], ensure_ascii=False)[:1500])
    batches = plan["execution_batches"]
    if not batches and not diag.get("ready_for_second_pass"):
        raise ValueError("第一輪仍有阻塞但沒有可執行任務；需要人工處理未知缺口")
    initial_phase = "sample" if not batches else "first_pass"
    state = {"schema_version": ws.VERSION, "phase": initial_phase,
             "initial_signature": diag["blocker_signature"],
             "observed_signature": diag["blocker_signature"],
             "observed_diagnostic": diag,
             "last_evidence": evidence,
             "formal_fingerprints": ws._formal_fingerprints(target),
             "batches": batches, "tasks": plan["rule_repair_tasks"],
             "completed_batches": [],
             "changed_rules": [], "mandatory_rules": [], "sample_records": {},
             "sample_chain": None, "inflight": None,
             "paused": False, "pause_reasons": []}
    ws._write_state(target / ws.STATE, state)
    return _result(state, include_plan=True)


def next_work(target: Path) -> dict:
    state = ws._load_state(target)
    ws._assert_state_current(target, state)
    if state["phase"] == "second_pass":
        from second_pass_layers import worklist
        return {"phase": "second_pass", "second_pass": worklist(target),
                "note": "候選需實際重讀來源並使用 review_safety --stage/--integrate 正式提交"}
    return _result(state, include_plan=True)


def _payload_scope(payload: dict, batch: dict, *, allow_finding_revision: bool,
                   previous: dict) -> None:
    """Only current batch's declared rule owners; never invent missing evidence."""
    allowed = set(batch["rule_ids"])
    mappings = {"checks": "id", "closures": None, "control_verifications": None,
                "decision_audits": None, "recheck_proof": None}
    for section, key in mappings.items():
        rows = payload.get(section, [] if key else {})
        if not isinstance(rows, list if key else dict):
            raise ValueError(f"{section} 型別無效")
        ids = {item.get(key) for item in rows if isinstance(item, dict)} if key else set(rows)
        if not ids <= allowed or (key and len(ids) != len(rows)):
            raise ValueError(f"{section} 包含非本批規則或重複規則")
    # A whole file_review replaces the record in the formal integrator.
    # Compare its per-rule evidence against the original; unchanged external
    # rules may be carried along, but must not be silently rewritten.
    existing_files = {row["path"]: row for row in previous.get("file_reviews", [])}
    submitted = payload.get("file_reviews", [])
    if not isinstance(submitted, list):
        raise ValueError("file_reviews 必須是陣列")
    paths: set[str] = set()
    for row in submitted:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            raise ValueError("file_reviews 缺少合法來源路徑")
        path = row["path"]
        if path in paths:
            raise ValueError("本批 file_reviews 來源路徑重複")
        paths.add(path)
        old = existing_files.get(path, {})
        old_reviews = {rr["rule_id"]: rr for rr in old.get("rule_reviews", [])
                       if isinstance(rr, dict) and isinstance(rr.get("rule_id"), str)}
        new_reviews = {rr["rule_id"]: rr for rr in row.get("rule_reviews", [])
                       if isinstance(rr, dict) and isinstance(rr.get("rule_id"), str)}
        if len(new_reviews) != len(row.get("rule_reviews", [])):
            raise ValueError("file_reviews.rule_reviews 缺少規則歸屬或重複")
        modified = {rid for rid in set(old_reviews) | set(new_reviews)
                    if old_reviews.get(rid) != new_reviews.get(rid)}
        if not modified <= allowed:
            raise ValueError("file_reviews 包含跨批次的逐條檢核變更")
        # Category screening is a file-wide claim: changing it can affect any
        # rule. Restrict changes when the file has external rule owners.
        if row.get("category_screening") != old.get("category_screening"):
            screening_owners = ws._rule_ids_from_file(row) | ws._rule_ids_from_file(old)
            if not screening_owners or not screening_owners <= allowed:
                raise ValueError("跨批次 category_screening 變更須分開授權及核對")
        # File-level metadata (including hashes and general summary) cannot be
        # rewritten while carrying other owners' already completed evidence.
        all_owners = ws._rule_ids_from_file(row) | ws._rule_ids_from_file(old)
        if row != old and not all_owners:
            raise ValueError("file_reviews 缺少可核對的規則歸屬，禁止跨批次寫入")
        external_owners = all_owners - allowed
        external_columns = {"rule_reviews", "category_screening"}
        if external_owners and any(
            row.get(k) != old.get(k)
            for k in set(row) | set(old) if k not in external_columns
        ):
            raise ValueError("外部規則共用逐檔紀錄的來源／摘要欄位不可跨批次改寫")
        if not modified and row == old:
            raise ValueError("file_reviews 未提供實質變更")
    prohibited = set(payload) & {"adversarial_reviews", "second_pass_samples"}
    if prohibited:
        raise ValueError("第一輪修復不可夾帶第二輪紀錄")
    for finding in payload.get("findings", []):
        if (not isinstance(finding, dict) or not finding.get("check_ids")
                or not set(finding.get("check_ids") or []) <= allowed):
            raise ValueError("Finding 必須關聯本批規則")
    if payload.get("finding_revisions") and not allow_finding_revision:
        raise ValueError("Finding 修訂須另行明確授權")


def apply_batch(target: Path, batch_id: str, payload_path: Path, *,
                allow_revision: bool, allow_finding_revision: bool = False) -> dict:
    """Wave 2: consumes explicit agent evidence; delegates ALL writes to formal guard."""
    if not allow_revision:
        raise ValueError("修改 completed 證據必須明確 --allow-revision，且已獲審查者授權")
    state = ws._load_state(target)
    if state["phase"] != "first_pass" or state.get("paused"):
        raise ValueError("不在可執行第一輪，或已有未處理的停止條件")
    ws._assert_state_current(target, state)
    expected = ws._next_batch(state)
    if not expected or expected["batch_id"] != batch_id:
        raise ValueError("指定批次不符合依賴或順序")
    ws._stage_clean(target)
    before = ws._assessment(target)
    payload = ws._read(payload_path)
    _payload_scope(payload, expected, allow_finding_revision=allow_finding_revision,
                   previous=before)
    current = state["observed_diagnostic"]
    from review_blockers import diagnose
    before_fingerprints = state["formal_fingerprints"]
    diag = diagnose(target, before)
    if diag["blocker_signature"] != state["observed_signature"]:
        raise ValueError("診斷指紋已變更，禁止套用舊批次")
    if not payload:
        raise ValueError("未提供實際已查核證據")
    from review_safety import stage, integrate
    state["inflight"] = {
        "phase": "first_pass", "batch_id": batch_id,
        "payload_sha256": _file_sha(payload_path),
        "payload_digest": _digest(payload),
        "prior_evidence": state["last_evidence"],
        "prior_fingerprints": state["formal_fingerprints"],
    }
    ws._write_state(target / ws.STATE, state)
    # A stage failure leaves existing formal data intact. A successful stage
    # followed by integration failure is intentionally left for manual repair.
    stage(target, payload_path)
    outcome = integrate(target, allow_revision=allow_revision,
                        allow_finding_revision=allow_finding_revision)
    if not outcome.get("applied"):
        raise ValueError("正式整合未套用任何證據")
    after = ws._assessment(target)
    updated = diagnose(target, after)
    regression = compare_rule_repair_diagnostics(current, updated)
    after_fingerprints = ws._formal_fingerprints(target)
    changed, mandatory = ws._formal_diff(before_fingerprints, after_fingerprints)
    state["changed_rules"] = sorted(set(state["changed_rules"]) | changed | mandatory)
    state["mandatory_rules"] = sorted(set(state["mandatory_rules"]) | mandatory)
    state["formal_fingerprints"] = after_fingerprints
    remaining = ws._batch_blockers(expected, state["tasks"]) & ws._blocker_keys(updated)
    no_progress = current["blocker_signature"] == updated["blocker_signature"]
    reasons = list(regression["pause_reasons"])
    if no_progress:
        reasons.append("本批診斷指紋未改變；不得以相同輸入反覆整合")
    if reasons:
        state["paused"] = True
        state["pause_reasons"] = sorted(set(reasons))
    if not remaining and not reasons:
        state["completed_batches"].append(batch_id)
    state["observed_diagnostic"] = updated
    state["observed_signature"] = updated["blocker_signature"]
    state["last_evidence"] = ws._evidence_state(target)
    state["inflight"] = None
    if ws._all_completed(state) and not state["paused"]:
        if updated.get("ready_for_second_pass"):
            state["phase"] = "sample"
        else:
            state["paused"] = True
            state["pause_reasons"] = ["所有原始批次已完成，但權威第一輪仍未通過"]
    ws._write_state(target / ws.STATE, state)
    return {**_result(state), "formal_integration": outcome,
            "regression": regression, "original_blockers_remaining": len(remaining),
            "batch_completed": batch_id in state["completed_batches"]}


def resume_after_investigation(target: Path, *, acknowledged: bool) -> dict:
    """Resume a paused checkpoint only after genuinely changed formal evidence.

    Never ignores new blockers, changed source snapshots, or an unchanged
    diagnostic. This is not an override of the safety or Journal guards.
    """
    if not acknowledged:
        raise ValueError("續跑須明確確認已調查阻塞原因")
    state = ws._load_state(target)
    if state.get("inflight") is not None:
        raise ValueError("待完成正式交易必須先執行 --reconcile，不能 --resume")
    if state["phase"] != "first_pass" or not state.get("paused"):
        raise ValueError("目前沒有可續跑的第一輪暫停狀態")
    evidence = ws._evidence_state(target)
    if evidence["source_snapshot_sha256"] != state["last_evidence"]["source_snapshot_sha256"]:
        raise ValueError("來源快照版本變動，不能沿用舊的修復批次")
    from review_blockers import diagnose
    current = diagnose(target, ws._assessment(target))
    current_fingerprints = ws._formal_fingerprints(target)
    external_changed, external_mandatory = ws._formal_diff(
        state["formal_fingerprints"], current_fingerprints)
    regression = compare_rule_repair_diagnostics(state["observed_diagnostic"], current)
    if regression["should_pause"]:
        raise ValueError("調查後仍有新阻塞／完整性問題：" +
                         "；".join(regression["pause_reasons"]))
    if current["blocker_signature"] == state["observed_signature"]:
        raise ValueError("權威阻塞指紋未改變，不能無條件解除暫停")
    state["observed_signature"] = current["blocker_signature"]
    state["observed_diagnostic"] = current
    state["last_evidence"] = evidence
    state["formal_fingerprints"] = current_fingerprints
    state["changed_rules"] = sorted(set(state["changed_rules"]) |
                                  external_changed | external_mandatory)
    state["mandatory_rules"] = sorted(set(state["mandatory_rules"]) | external_mandatory)
    state["paused"] = False
    state["pause_reasons"] = []
    # Reconcile pending tasks only against actual authoritative disappearance
    # of their original blocker identities. A mere acknowledgement clears none.
    present = ws._blocker_keys(current)
    completed = set(state["completed_batches"])
    for batch in state["batches"]:
        if batch["batch_id"] in completed:
            continue
        if (set(batch["depends_on_batch_ids"]) <= completed
                and not (ws._batch_blockers(batch, state["tasks"]) & present)):
            completed.add(batch["batch_id"])
    state["completed_batches"] = [b["batch_id"] for b in state["batches"]
                                  if b["batch_id"] in completed]
    if ws._all_completed(state):
        if current.get("ready_for_second_pass"):
            state["phase"] = "sample"
        else:
            state["paused"] = True
            state["pause_reasons"] = ["原始任務已完，但權威診斷仍存在缺口"]
    ws._write_state(target / ws.STATE, state)
    return {**_result(state), "regression": regression,
            "note": "已在完整性核對及權威診斷改變後續跑；不構成新的安全結論"}


def sample_plan(target: Path) -> dict:
    """Wave 3: select only real changed rules, enforce high-risk full coverage."""
    state = ws._load_state(target)
    ws._assert_state_current(target, state)
    if state.get("paused") or state["phase"] not in {"sample", "second_pass"}:
        raise ValueError("第一輪尚未正式結案，或協調器被停止")
    policy = _sample_policy(state["changed_rules"], state["mandatory_rules"],
                            state["initial_signature"], ws._assessment(target))
    if state.get("sample_policy") is not None and state["sample_policy"] != policy:
        raise ValueError("固定抽樣計畫與現況不一致，禁止靜默換樣")
    state["sample_policy"] = policy
    ws._write_state(target / ws.STATE, state)
    return {"phase": state["phase"], "sampling": policy,
            "remaining_rules": sorted(set(policy["selected_rules"]) -
                                      set(state["sample_records"])),
            "read_only_of_formal_evidence": True}


def record_sample(target: Path, receipt_file: Path) -> dict:
    """Record reviewer-supplied verification; does not attest reviewer identity."""
    state = ws._load_state(target)
    ws._assert_state_current(target, state)
    if state["phase"] != "sample" or state.get("paused") or not state.get("sample_policy"):
        raise ValueError("未到抽樣階段，或尚未固定抽樣計畫")
    receipt = ws._read(receipt_file)
    rule = receipt.get("rule_id")
    if rule not in state["sample_policy"]["selected_rules"] or rule in state["sample_records"]:
        raise ValueError("規則不在固定樣本內或已簽認")
    if not isinstance(receipt.get("reviewer"), str) or len(receipt["reviewer"].strip()) < 4:
        raise ValueError("須填寫人工覆核者身分")
    if not isinstance(receipt.get("review_summary"), str) or len(receipt["review_summary"].strip()) < 40:
        raise ValueError("須有具體 40 字以上的重新閱讀查核內容")
    if receipt.get("outcome") != "verified":
        raise ValueError("未查核完或發現問題者不得計入已覆核")
    reviewed_on = receipt.get("reviewed_on")
    if not isinstance(reviewed_on, str) or date.fromisoformat(reviewed_on) > date.today():
        raise ValueError("覆核日期無效")
    proof = receipt.get("evidence")
    if not isinstance(proof, dict) or not isinstance(proof.get("path"), str):
        raise ValueError("缺少來源證據")
    from review_snapshot import SNAPSHOT as FORMAL_SNAPSHOT
    snapshot = ws._read(target / ws.REPORT / FORMAL_SNAPSHOT)
    path = proof["path"]
    source_hash = (snapshot.get("source_hashes") or {}).get(path)
    original = target / path
    candidate = original.resolve()
    if (not source_hash or original.is_symlink()
            or not candidate.is_relative_to(target.resolve())
            or not candidate.is_file() or not digest_matches(source_hash, candidate.read_bytes())):
        raise ValueError("抽樣來源不在可信快照內或 SHA256 不符")
    start, end = proof.get("line_start"), proof.get("line_end")
    if type(start) is not int or type(end) is not int or start < 1 or end < start:
        raise ValueError("證據行號無效")
    from source_reader import read_source_text
    source_text, _ = read_source_text(candidate)
    if end > len(source_text.splitlines()):
        raise ValueError("抽樣證據超出實際來源行號")
    assessment = ws._assessment(target)
    check = next((r for r in assessment.get("checks", [])
                  if isinstance(r, dict) and r.get("id") == rule), None)
    anchors = set()
    if isinstance(check, dict):
        anchors.update(p for p in (check.get("execution") or {}).get("inspected_paths", [])
                       if isinstance(p, str))
        anchors.update(e.get("path") for e in check.get("evidence", [])
                       if isinstance(e, dict) and isinstance(e.get("path"), str))
    for row in assessment.get("file_reviews") or []:
        if isinstance(row, dict) and rule in ws._rule_ids_from_file(row):
            anchors.add(row.get("path"))
    if path not in anchors:
        raise ValueError("抽樣路徑未與本規則正式來源證據建立關聯")
    state["sample_chain"] = sample_chain_append(
        state.get("sample_chain"), receipt,
        expected_manifest_sha256=state["last_evidence"].get("manifest_sha256"))
    state["sample_records"][rule] = {"reviewer": receipt["reviewer"],
                                     "reviewed_on": reviewed_on, "outcome": "verified",
                                     "receipt_sha256": _digest(receipt),
                                     "source_sha256": source_hash,
                                     "claimed_independence": "unverified"}
    ws._write_state(target / ws.STATE, state)
    return {"verified_sample_rules": sorted(state["sample_records"]),
            "remaining_rules": sorted(set(state["sample_policy"]["selected_rules"]) -
                                      set(state["sample_records"])),
            "caution": "紀錄不構成可信人身認證，也不自動完成正式第二輪"}


def begin_second_pass(target: Path) -> dict:
    """Wave 4: transition ONLY through existing first-pass security gate."""
    state = ws._load_state(target)
    ws._assert_state_current(target, state)
    if state.get("paused") or state["phase"] != "sample" or not ws._all_completed(state):
        raise ValueError("第一輪批次尚未全部完成或有未處理停止條件")
    policy = state.get("sample_policy")
    if not isinstance(policy, dict) or set(policy["selected_rules"]) != set(state["sample_records"]):
        raise ValueError("人工風險抽樣未全部完成，不得進入第二輪")
    chain = state.get("sample_chain")
    if chain is not None:
        verify_sample_chain(chain)
    if policy["selected_rules"] and (not chain or
            set(entry["rule_id"] for entry in chain["entries"]) !=
            set(policy["selected_rules"]) or
            chain["base_manifest_sha256"] != state["last_evidence"].get("manifest_sha256") or
            any(entry["receipt_sha256"] !=
                state["sample_records"][entry["rule_id"]]["receipt_sha256"]
                for entry in chain["entries"])):
        raise ValueError("抽樣收據鏈未完整綁定目前 Manifest；不可啟動第二輪")
    from review_blockers import diagnose
    assessment = ws._assessment(target)
    current = diagnose(target, assessment)
    if (current["blocker_signature"] != state["observed_signature"]
            or not current["ready_for_second_pass"]):
        raise ValueError("權威第一輪守門尚未通過")
    from adversarial_recheck import begin_second_pass as formal_begin
    state["inflight"] = {
        "phase": "baseline", "batch_id": "first-pass-baseline",
        "prior_evidence": state["last_evidence"],
        "prior_fingerprints": state["formal_fingerprints"],
    }
    ws._write_state(target / ws.STATE, state)
    result = formal_begin(target, assessment)
    # Baseline and fixed sampling are formal Journal-protected data; this local
    # sidecar is not. It only records the handoff.
    state["phase"] = "second_pass"
    state["last_evidence"] = ws._evidence_state(target)
    state["formal_fingerprints"] = ws._formal_fingerprints(target)
    state["inflight"] = None
    ws._write_state(target / ws.STATE, state)
    from second_pass_layers import worklist
    return {"formal_baseline": result, "second_pass": worklist(target),
            "claim": "已呼叫正式固定第一輪錨點；未宣稱已完成反向覆核或獨立盲審"}


def apply_second_pass(target: Path, payload_path: Path, *,
                      allow_revision: bool = False,
                      allow_finding_revision: bool = False) -> dict:
    """Wave 4: accept real targeted adversarial evidence via formal transaction.

    This is NOT an L1/L2 agent and cannot generate findings or judgments.
    """
    state = ws._load_state(target)
    if state["phase"] != "second_pass" or state.get("paused"):
        raise ValueError("第二輪未正式啟動或已暫停")
    ws._assert_state_current(target, state)
    ws._stage_clean(target)
    from second_pass_layers import worklist
    available = worklist(target)
    if not available.get("ready"):
        raise ValueError("第二輪正式工作清單尚未建立或無效")
    allowed_rules = {t["rule_id"] for t in available.get("rule_tasks", [])}
    allowed_paths = {t["path"] for t in available.get("sample_tasks", [])}
    payload = ws._read(payload_path)
    if not payload:
        raise ValueError("第二輪必須提供已查核的正式證據")
    if set(payload) - {"adversarial_reviews", "second_pass_samples", "checks",
                       "file_reviews", "findings", "finding_revisions", "closures",
                       "control_verifications", "decision_audits"}:
        raise ValueError("第二輪含不支援的證據欄位")
    if not (payload.get("adversarial_reviews") or payload.get("second_pass_samples")):
        raise ValueError("缺少反向複核或正式來源抽樣紀錄")
    for field, allowed in (("adversarial_reviews", allowed_rules),
                           ("second_pass_samples", allowed_paths)):
        items = payload.get(field) or {}
        if not isinstance(items, dict) or not set(items) <= allowed:
            raise ValueError(f"{field} 不在目前第二輪工作批次")
    prior = ws._assessment(target)
    _payload_scope({k: v for k, v in payload.items()
                    if k not in {"adversarial_reviews", "second_pass_samples"}},
                   {"rule_ids": sorted(allowed_rules)},
                   allow_finding_revision=allow_finding_revision,
                   previous=prior)
    from review_safety import stage, integrate
    state["inflight"] = {
        "phase": "second_pass", "batch_id": "second-pass",
        "payload_sha256": _file_sha(payload_path),
        "prior_evidence": state["last_evidence"],
        "prior_fingerprints": state["formal_fingerprints"],
    }
    ws._write_state(target / ws.STATE, state)
    stage(target, payload_path)
    outcome = integrate(target, allow_revision=allow_revision,
                        allow_finding_revision=allow_finding_revision)
    if not outcome.get("applied"):
        raise ValueError("第二輪正式交易未整合任何紀錄")
    state["last_evidence"] = ws._evidence_state(target)
    state["formal_fingerprints"] = ws._formal_fingerprints(target)
    state["inflight"] = None
    ws._write_state(target / ws.STATE, state)
    updated = worklist(target)
    return {"phase": "second_pass", "formal_integration": outcome,
            "rules_pending": updated.get("rules_pending"),
            "samples_pending": updated.get("samples_pending"),
            "ready_for_report": False,
            "limitations": "第二輪完成狀態以正式 Journal／驗證器為準；不會自動改判、補證或核准交付"}


def verify_second_pass(target: Path) -> dict:
    """Observe actual formal adversarial records; never marks rules completed."""
    state = ws._load_state(target)
    if state["phase"] != "second_pass":
        raise ValueError("尚未進入正式第二輪")
    ws._assert_state_current(target, state)
    from second_pass_layers import worklist
    work = worklist(target)
    from review_safety import safety_errors
    problems = safety_errors(target, ws._assessment(target))
    return {"phase": "second_pass", "formal_second_pass": work,
            "safety_valid": not problems,
            "safety_errors": problems[:30],
            "second_pass_worklist_complete": bool(work.get("ready") and
                                                    work.get("rules_pending") == 0 and
                                                    work.get("samples_pending") == 0 and not problems),
            "ready_for_report": False,
            "limitations": "只表示第二輪工作與安全驗證狀態；正式交付仍須非精簡完整佇列 ready_for_report=true 及 complete_review.py"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="受控 Wave 0–4 資安補查協調器，不自動生成證據")
    parser.add_argument("--target", type=Path, default=Path.cwd())
    operations = parser.add_mutually_exclusive_group(required=True)
    for flag in ("start", "next", "agent-next", "reconcile", "finalize", "resume", "sample-plan",
                 "begin-second-pass", "verify-second-pass"):
        operations.add_argument("--" + flag, action="store_true")
    operations.add_argument("--apply-batch", metavar="BATCH_ID")
    operations.add_argument("--abort-uncommitted", metavar="BATCH_ID")
    operations.add_argument("--inspect-uncommitted", metavar="BATCH_ID")
    operations.add_argument("--apply-second-pass", action="store_true")
    operations.add_argument("--record-sample", type=Path, metavar="RECEIPT_JSON")
    parser.add_argument("--payload", type=Path)
    parser.add_argument("--allow-revision", action="store_true")
    parser.add_argument("--allow-finding-revision", action="store_true")
    parser.add_argument("--acknowledge-investigation", action="store_true")
    parser.add_argument("--expected-staged-sha256")
    parser.add_argument("--allow-unbound-legacy-stage", action="store_true")
    args = parser.parse_args(argv)
    target = args.target.resolve()
    if not target.is_dir():
        parser.error("受測目錄不存在")
    try:
        if (args.start or args.apply_batch or args.apply_second_pass or args.record_sample
                or args.sample_plan or args.begin_second_pass or args.resume
                or args.reconcile or args.finalize or args.abort_uncommitted):
            with ws._single_writer(target):
                if args.start:
                    result = start(target)
                elif args.abort_uncommitted:
                    result = abort_uncommitted(
                        target, args.abort_uncommitted,
                        payload_path=args.payload,
                        acknowledged=args.acknowledge_investigation,
                        expected_staged_sha256=args.expected_staged_sha256,
                        allow_unbound_legacy=args.allow_unbound_legacy_stage)
                elif args.reconcile:
                    result = reconcile(target, acknowledged=args.acknowledge_investigation)
                elif args.finalize:
                    result = finalize(target)
                elif args.resume:
                    result = resume_after_investigation(
                        target, acknowledged=args.acknowledge_investigation)
                elif args.apply_batch:
                    if not args.payload:
                        raise ValueError("--apply-batch 必須提供 --payload")
                    result = apply_batch(target, args.apply_batch, args.payload,
                                         allow_revision=args.allow_revision,
                                         allow_finding_revision=args.allow_finding_revision)
                elif args.apply_second_pass:
                    if not args.payload:
                        raise ValueError("--apply-second-pass 必須提供 --payload")
                    result = apply_second_pass(
                        target, args.payload, allow_revision=args.allow_revision,
                        allow_finding_revision=args.allow_finding_revision)
                elif args.record_sample:
                    result = record_sample(target, args.record_sample)
                elif args.sample_plan:
                    result = sample_plan(target)
                else:
                    result = begin_second_pass(target)
        elif args.inspect_uncommitted:
            result = inspect_uncommitted(
                target, args.inspect_uncommitted, payload_path=args.payload,
                expected_staged_sha256=args.expected_staged_sha256,
                allow_unbound_legacy=args.allow_unbound_legacy_stage)
        elif args.next:
            result = next_work(target)
        elif args.agent_next:
            result = agent_next(target)
        else:
            result = verify_second_pass(target)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "blocked", "error": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 3 if result.get("paused") else 0


if __name__ == "__main__":
    raise SystemExit(main())
