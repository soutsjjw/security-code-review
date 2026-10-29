#!/usr/bin/env python3
"""Wave 0–4 fail-closed coordinator for REAL, agent-supplied security review.

The coordinator never writes source, fabricates evidence, decides Pass/Fail, or
changes the authoritative assessment directly. The only formal write path is
review_safety.stage/integrate and begin_second_pass; all other state is an
untrusted operational checkpoint under logs/, not a signed Journal.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import date
import hashlib
import json
import math
import os
from pathlib import Path
import sys
from typing import Any

REPORT = Path("reports/security-code-review")
STATE = REPORT / "logs/repair-waves/state.json"
SNAPSHOT = REPORT / "analysis/source-snapshot.json"
VERSION = 1
RISK_PREFIXES = ("AC", "AU", "CR", "DP", "IN")


def _read(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path.name}: 必須是 JSON 物件")
    return data


def _digest(data: Any) -> str:
    return hashlib.sha256(json.dumps(data, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":")).encode("utf-8")).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _assessment(target: Path) -> dict[str, Any]:
    return _read(target / REPORT / "assessment.json")


def _evidence_state(target: Path) -> dict[str, str]:
    from review_safety import snapshot_errors
    from evidence_integrity import errors as integrity_errors
    failures = snapshot_errors(target) + integrity_errors(target)
    if failures:
        raise ValueError("正式來源／完整性守門未通過：" + "；".join(failures[:8]))
    assessment = target / REPORT / "assessment.json"
    from review_safety import SNAPSHOT as FORMAL_SNAPSHOT
    snap_path = target / REPORT / FORMAL_SNAPSHOT
    if not assessment.is_file() or not snap_path.is_file():
        raise ValueError("缺少正式 assessment 或來源快照")
    return {"assessment_sha256": _file_sha(assessment),
            "source_snapshot_sha256": _file_sha(snap_path)}


def _stage_clean(target: Path) -> None:
    from review_safety import STAGED
    directory = target / REPORT / STAGED
    if directory.is_dir() and list(directory.glob("*.json")):
        raise ValueError("存在其他待整合暫存資料；先合法處理，不得混入本批")


def _diagnose_and_plan(target: Path) -> tuple[dict, dict]:
    from review_blockers import diagnose
    from first_pass_repair import repair_plan
    assessment = _assessment(target)
    diagnosis = diagnose(target, assessment)
    plan = repair_plan(assessment, diagnosis)
    return diagnosis, plan


def _write_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError("不接受指向外部的 checkpoint 符號連結")
    temp = path.with_name(path.name + ".pending")
    if temp.exists() or temp.is_symlink():
        raise ValueError("發現未完成的 checkpoint 暫存；需先人工排除")
    with temp.open("x", encoding="utf-8") as fp:
        json.dump(state, fp, ensure_ascii=False, sort_keys=True, indent=2)
        fp.flush()
        os.fsync(fp.fileno())
    os.replace(temp, path)


@contextmanager
def _single_writer(target: Path):
    lock = target / STATE.parent / ".writer.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ValueError("已有修復協調器正在寫入，或舊鎖尚未人工調查") from exc
    try:
        os.close(fd)
        yield
    finally:
        lock.unlink(missing_ok=True)


def _load_state(target: Path) -> dict:
    path = target / STATE
    if path.is_symlink():
        raise ValueError("不接受 checkpoint 符號連結")
    state = _read(path)
    if state.get("schema_version") != VERSION or not isinstance(state.get("batches"), list):
        raise ValueError("不認得的修復 checkpoint 版本")
    return state


def _assert_state_current(target: Path, state: dict) -> None:
    current = _evidence_state(target)
    if current != state.get("last_evidence"):
        raise ValueError("正式資料或來源快照已在協調器外變更；停止並人工核對")


def _all_completed(state: dict) -> bool:
    return len(state["completed_batches"]) == len(state["batches"])


def _next_batch(state: dict) -> dict | None:
    done = set(state["completed_batches"])
    for batch in state["batches"]:
        if batch["batch_id"] not in done and set(batch["depends_on_batch_ids"]) <= done:
            return batch
    return None


def _batch_blockers(batch: dict, tasks: list[dict]) -> set[tuple[str, tuple[str, ...]]]:
    ids = set(batch["task_ids"])
    return {(item["message"], tuple(sorted(item["rule_ids"])))
            for task in tasks if task["task_id"] in ids
            for item in task["blocker_details"]}


def _blocker_keys(diagnostic: dict) -> set[tuple[str, tuple[str, ...]]]:
    return {(str(b["message"]), tuple(sorted(b.get("rule_ids") or [])))
            for b in diagnostic.get("blockers", [])}


def _sample_policy(changed: list[str], mandatory: list[str], initial_signature: str,
                   assessment: dict) -> dict:
    """Risk-first, seeded and deterministic, with mandatory cases never sampled away."""
    rules = sorted(set(changed))
    force = sorted(set(mandatory) & set(rules))
    count = min(len(rules), max(5, math.ceil(len(rules) * 0.1))) if rules else 0
    checks = {c.get("id"): c for c in assessment.get("checks", []) if isinstance(c, dict)}
    def rank(rule_id: str) -> tuple:
        entry = checks.get(rule_id, {})
        score = int(entry.get("status") == "fail") * 5
        score += int(rule_id[:2] in RISK_PREFIXES) * 2
        return (-score, hashlib.sha256((initial_signature + ":" + rule_id).encode()).hexdigest())
    selected = sorted(set(force) | set(sorted((r for r in rules if r not in force),
                                               key=rank)[:max(0, count - len(force))]))
    return {"rule_count": len(rules), "minimum_sample_count": count,
            "mandatory_rules": force, "selected_rules": selected,
            "selection": "all-high-risk-plus-deterministic-risk-strata",
            "seed_binding": initial_signature,
            "limitations": "抽樣紀錄需人工實際核對；並非獨立代理身分或來源真實性的自動證明"}


def _result(state: dict, *, include_plan: bool = False) -> dict:
    pending = _next_batch(state)
    return {"schema_version": VERSION, "phase": state["phase"],
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
    if (target / STATE).exists():
        raise ValueError("已有 checkpoint；使用 --next 續跑，禁止重新初始化覆蓋")
    _stage_clean(target)
    evidence = _evidence_state(target)
    diag, plan = _diagnose_and_plan(target)
    if not plan["task_coverage"]["valid"]:
        raise ValueError("權威阻塞無法完整排程，禁止啟動：" +
                         json.dumps(plan["task_coverage"], ensure_ascii=False)[:1500])
    batches = plan["execution_batches"]
    initial_phase = "sample" if not batches and diag.get("ready_for_second_pass") else "first_pass"
    state = {"schema_version": VERSION, "phase": initial_phase,
             "initial_signature": diag["blocker_signature"],
             "observed_signature": diag["blocker_signature"],
             "observed_diagnostic": diag,
             "last_evidence": evidence,
             "batches": batches, "tasks": plan["rule_repair_tasks"],
             "completed_batches": [],
             "changed_rules": [], "mandatory_rules": [], "sample_records": {},
             "paused": False, "pause_reasons": []}
    _write_state(target / STATE, state)
    return _result(state, include_plan=True)


def next_work(target: Path) -> dict:
    state = _load_state(target)
    _assert_state_current(target, state)
    if state["phase"] == "second_pass":
        from second_pass_layers import worklist
        return {"phase": "second_pass", "second_pass": worklist(target),
                "note": "候選需實際重讀來源並使用 review_safety --stage/--integrate 正式提交"}
    return _result(state, include_plan=True)


def _payload_scope(payload: dict, batch: dict, *, allow_finding_revision: bool) -> None:
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
    state = _load_state(target)
    if state["phase"] != "first_pass" or state.get("paused"):
        raise ValueError("不在可執行第一輪，或已有未處理的停止條件")
    _assert_state_current(target, state)
    expected = _next_batch(state)
    if not expected or expected["batch_id"] != batch_id:
        raise ValueError("指定批次不符合依賴或順序")
    _stage_clean(target)
    payload = _read(payload_path)
    _payload_scope(payload, expected, allow_finding_revision=allow_finding_revision)
    current = state["observed_diagnostic"]
    from review_blockers import diagnose
    before = _assessment(target)
    diag = diagnose(target, before)
    if diag["blocker_signature"] != state["observed_signature"]:
        raise ValueError("診斷指紋已變更，禁止套用舊批次")
    if not payload:
        raise ValueError("未提供實際已查核證據")
    from review_safety import stage, integrate
    # A stage failure leaves existing formal data intact. A successful stage
    # followed by integration failure is intentionally left for manual repair.
    stage(target, payload_path)
    outcome = integrate(target, allow_revision=allow_revision,
                        allow_finding_revision=allow_finding_revision)
    if not outcome.get("applied"):
        raise ValueError("正式整合未套用任何證據")
    after = _assessment(target)
    updated = diagnose(target, after)
    from rule_repair_tasks import compare_rule_repair_diagnostics
    regression = compare_rule_repair_diagnostics(current, updated)
    before_checks = {c["id"]: c for c in before.get("checks", [])}
    after_checks = {c["id"]: c for c in after.get("checks", [])}
    changed = {rid for rid in after_checks if before_checks.get(rid) != after_checks[rid]}
    # Non-check formal proof is still real changed work and needs sampling.
    changed.update(set(payload.get("closures") or {}))
    changed.update(set(payload.get("control_verifications") or {}))
    changed.update(set(payload.get("decision_audits") or {}))
    changed.update(set(payload.get("recheck_proof") or {}))
    if payload.get("file_reviews"):
        changed.update(expected["rule_ids"])
    for row in payload.get("file_reviews") or []:
        for review in row.get("rule_reviews") or []:
            if isinstance(review, dict) and isinstance(review.get("rule_id"), str):
                changed.add(review["rule_id"])
    state["changed_rules"] = sorted(set(state["changed_rules"]) | changed)
    mandatory = set(state["mandatory_rules"])
    old_findings = {f["id"]: f for f in before.get("findings", [])}
    new_findings = {f["id"]: f for f in after.get("findings", [])}
    if any(old_findings.get(fid) != f for fid, f in new_findings.items()):
        for f in new_findings.values():
            if old_findings.get(f["id"]) != f:
                mandatory.update(f.get("check_ids") or [])
    for rid in changed:
        old_status = (before_checks.get(rid) or {}).get("status")
        new_status = (after_checks.get(rid) or {}).get("status")
        if old_status != new_status and "fail" in (old_status, new_status):
            mandatory.add(rid)
    mandatory.update(payload.get("closures") or {})
    mandatory.update(payload.get("decision_audits") or {})
    state["changed_rules"] = sorted(set(state["changed_rules"]) | mandatory)
    state["mandatory_rules"] = sorted(mandatory)
    remaining = _batch_blockers(expected, state["tasks"]) & _blocker_keys(updated)
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
    state["last_evidence"] = _evidence_state(target)
    if _all_completed(state) and not state["paused"]:
        if updated.get("ready_for_second_pass"):
            state["phase"] = "sample"
        else:
            state["paused"] = True
            state["pause_reasons"] = ["所有原始批次已完成，但權威第一輪仍未通過"]
    _write_state(target / STATE, state)
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
    state = _load_state(target)
    if state["phase"] != "first_pass" or not state.get("paused"):
        raise ValueError("目前沒有可續跑的第一輪暫停狀態")
    evidence = _evidence_state(target)
    if evidence["source_snapshot_sha256"] != state["last_evidence"]["source_snapshot_sha256"]:
        raise ValueError("來源快照版本變動，不能沿用舊的修復批次")
    from review_blockers import diagnose
    from rule_repair_tasks import compare_rule_repair_diagnostics
    current = diagnose(target, _assessment(target))
    regression = compare_rule_repair_diagnostics(state["observed_diagnostic"], current)
    if regression["should_pause"]:
        raise ValueError("調查後仍有新阻塞／完整性問題：" +
                         "；".join(regression["pause_reasons"]))
    if current["blocker_signature"] == state["observed_signature"]:
        raise ValueError("權威阻塞指紋未改變，不能無條件解除暫停")
    state["observed_signature"] = current["blocker_signature"]
    state["observed_diagnostic"] = current
    state["last_evidence"] = evidence
    state["paused"] = False
    state["pause_reasons"] = []
    # Reconcile pending tasks only against actual authoritative disappearance
    # of their original blocker identities. A mere acknowledgement clears none.
    present = _blocker_keys(current)
    completed = set(state["completed_batches"])
    for batch in state["batches"]:
        if batch["batch_id"] in completed:
            continue
        if (set(batch["depends_on_batch_ids"]) <= completed
                and not (_batch_blockers(batch, state["tasks"]) & present)):
            completed.add(batch["batch_id"])
    state["completed_batches"] = [b["batch_id"] for b in state["batches"]
                                  if b["batch_id"] in completed]
    if _all_completed(state):
        if current.get("ready_for_second_pass"):
            state["phase"] = "sample"
        else:
            state["paused"] = True
            state["pause_reasons"] = ["原始任務已完，但權威診斷仍存在缺口"]
    _write_state(target / STATE, state)
    return {**_result(state), "regression": regression,
            "note": "已在完整性核對及權威診斷改變後續跑；不構成新的安全結論"}



def sample_plan(target: Path) -> dict:
    """Wave 3: select only real changed rules, enforce high-risk full coverage."""
    state = _load_state(target)
    _assert_state_current(target, state)
    if state.get("paused") or state["phase"] not in {"sample", "second_pass"}:
        raise ValueError("第一輪尚未正式結案，或協調器被停止")
    policy = _sample_policy(state["changed_rules"], state["mandatory_rules"],
                            state["initial_signature"], _assessment(target))
    if state.get("sample_policy") is not None and state["sample_policy"] != policy:
        raise ValueError("固定抽樣計畫與現況不一致，禁止靜默換樣")
    state["sample_policy"] = policy
    _write_state(target / STATE, state)
    return {"phase": state["phase"], "sampling": policy,
            "remaining_rules": sorted(set(policy["selected_rules"]) -
                                      set(state["sample_records"])),
            "read_only_of_formal_evidence": True}


def record_sample(target: Path, receipt_file: Path) -> dict:
    """Record reviewer-supplied verification; does not attest reviewer identity."""
    state = _load_state(target)
    _assert_state_current(target, state)
    if state["phase"] != "sample" or state.get("paused") or not state.get("sample_policy"):
        raise ValueError("未到抽樣階段，或尚未固定抽樣計畫")
    receipt = _read(receipt_file)
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
    from review_safety import SNAPSHOT as FORMAL_SNAPSHOT
    snapshot = _read(target / REPORT / FORMAL_SNAPSHOT)
    path = proof["path"]
    source_hash = (snapshot.get("source_hashes") or {}).get(path)
    original = target / path
    candidate = original.resolve()
    from source_reader import digest_matches
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
    state["sample_records"][rule] = {"reviewer": receipt["reviewer"],
                                     "reviewed_on": reviewed_on, "outcome": "verified",
                                     "receipt_sha256": _digest(receipt),
                                     "source_sha256": source_hash,
                                     "claimed_independence": "unverified"}
    _write_state(target / STATE, state)
    return {"verified_sample_rules": sorted(state["sample_records"]),
            "remaining_rules": sorted(set(state["sample_policy"]["selected_rules"]) -
                                      set(state["sample_records"])),
            "caution": "紀錄不構成可信人身認證，也不自動完成正式第二輪"}


def begin_second_pass(target: Path) -> dict:
    """Wave 4: transition ONLY through existing first-pass security gate."""
    state = _load_state(target)
    _assert_state_current(target, state)
    if state.get("paused") or state["phase"] != "sample" or not _all_completed(state):
        raise ValueError("第一輪批次尚未全部完成或有未處理停止條件")
    policy = state.get("sample_policy")
    if not isinstance(policy, dict) or set(policy["selected_rules"]) != set(state["sample_records"]):
        raise ValueError("人工風險抽樣未全部完成，不得進入第二輪")
    from review_blockers import diagnose
    assessment = _assessment(target)
    current = diagnose(target, assessment)
    if (current["blocker_signature"] != state["observed_signature"]
            or not current["ready_for_second_pass"]):
        raise ValueError("權威第一輪守門尚未通過")
    from adversarial_recheck import begin_second_pass as formal_begin
    result = formal_begin(target, assessment)
    # Baseline and fixed sampling are formal Journal-protected data; this local
    # sidecar is not. It only records the handoff.
    state["phase"] = "second_pass"
    state["last_evidence"] = _evidence_state(target)
    _write_state(target / STATE, state)
    from second_pass_layers import worklist
    return {"formal_baseline": result, "second_pass": worklist(target),
            "claim": "已呼叫正式固定第一輪錨點；未宣稱已完成反向覆核或獨立盲審"}


def verify_second_pass(target: Path) -> dict:
    """Observe actual formal adversarial records; never marks rules completed."""
    state = _load_state(target)
    if state["phase"] != "second_pass":
        raise ValueError("尚未進入正式第二輪")
    _assert_state_current(target, state)
    from second_pass_layers import worklist
    work = worklist(target)
    from review_safety import safety_errors
    problems = safety_errors(target, _assessment(target))
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
    for flag in ("start", "next", "resume", "sample-plan", "begin-second-pass", "verify-second-pass"):
        operations.add_argument("--" + flag, action="store_true")
    operations.add_argument("--apply-batch", metavar="BATCH_ID")
    operations.add_argument("--record-sample", type=Path, metavar="RECEIPT_JSON")
    parser.add_argument("--payload", type=Path)
    parser.add_argument("--allow-revision", action="store_true")
    parser.add_argument("--allow-finding-revision", action="store_true")
    parser.add_argument("--acknowledge-investigation", action="store_true")
    args = parser.parse_args(argv)
    target = args.target.resolve()
    if not target.is_dir():
        parser.error("受測目錄不存在")
    try:
        if args.start or args.apply_batch or args.record_sample or args.sample_plan or args.begin_second_pass or args.resume:
            with _single_writer(target):
                if args.start:
                    result = start(target)
                elif args.resume:
                    result = resume_after_investigation(
                        target, acknowledged=args.acknowledge_investigation)
                elif args.apply_batch:
                    if not args.payload:
                        raise ValueError("--apply-batch 必須提供 --payload")
                    result = apply_batch(target, args.apply_batch, args.payload,
                                         allow_revision=args.allow_revision,
                                         allow_finding_revision=args.allow_finding_revision)
                elif args.record_sample:
                    result = record_sample(target, args.record_sample)
                elif args.sample_plan:
                    result = sample_plan(target)
                else:
                    result = begin_second_pass(target)
        elif args.next:
            result = next_work(target)
        else:
            result = verify_second_pass(target)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "blocked", "error": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 3 if result.get("paused") else 0


if __name__ == "__main__":
    raise SystemExit(main())
