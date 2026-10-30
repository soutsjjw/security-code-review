#!/usr/bin/env python3
"""Wave crash reconciliation and official final-report handoff.

Reconciliation never replays a transaction and never edits official evidence.
"""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys
import review_waves_state as ws
from review_core import file_sha256 as _file_sha, REPORT_ROOT
from review_waves_contracts import independence_metadata, verify_sample_chain, work_contract
from rule_repair_tasks import compare_rule_repair_diagnostics

DELIVERY = REPORT_ROOT / "logs/repair-waves/delivery.json"


def agent_next(target: Path) -> dict:
    state = ws.load_state(target)
    ws.assert_state_current(target, state)
    work = None
    if state["phase"] == "second_pass":
        from second_pass_layers import worklist
        work = worklist(target)
    return work_contract(target, state, second_pass=work)


def reconcile(target: Path, *, acknowledged: bool) -> dict:
    """Compare authoritative post-crash evidence to the saved pre-transaction.

    Only an actual authorized formal write can advance the checkpoint.
    """
    if not acknowledged:
        raise ValueError("必須明確承認已調查中斷的正式交易")
    state = ws.load_state(target)
    intent = state.get("inflight")
    if not isinstance(intent, dict):
        raise ValueError("沒有待對帳的正式交易意圖")
    evidence = ws.evidence_state(target)
    if evidence["source_snapshot_sha256"] != intent["prior_evidence"]["source_snapshot_sha256"]:
        raise ValueError("來源快照已改變，須重新定義審查基準")
    before_tracks = intent["prior_evidence"].get("tracked_sha256") or {}
    after_tracks = evidence.get("tracked_sha256") or {}
    modified_tracks = {key for key in set(before_tracks) | set(after_tracks)
                       if before_tracks.get(key) != after_tracks.get(key)}
    scopes = {
        "first_pass": {"assessment.json", "analysis/rule-closures.json",
                       "analysis/control-verifications.json", "analysis/decision-audits.json",
                       "analysis/recheck-required.json"},
        "baseline": {"analysis/first-pass-baseline.json", "analysis/adversarial-reviews.json"},
        "second_pass": {"assessment.json", "analysis/rule-closures.json",
                        "analysis/control-verifications.json", "analysis/decision-audits.json",
                        "analysis/adversarial-reviews.json"},
    }
    if modified_tracks - scopes.get(intent.get("phase"), set()):
        raise ValueError("正式工件異動超出本次交易允許範圍，禁止自動對帳")
    current_fps = ws.formal_fingerprints(target)
    prior = intent["prior_fingerprints"]
    if current_fps == prior:
        raise ValueError("未觀察到完成的正式證據變動；應調查 staged 與 Journal，不得重播")
    changed, mandatory = ws.formal_diff(prior, current_fps)
    if intent["phase"] == "first_pass":
        from review_blockers import diagnose
        current = diagnose(target, ws.load_assessment(target))
        reg = compare_rule_repair_diagnostics(state["observed_diagnostic"], current)
        if reg["should_pause"]:
            raise ValueError("正式交易完成後仍有新增阻塞／完整性風險：" +
                             "；".join(reg["pause_reasons"]))
        batch = next((x for x in state["batches"]
                      if x["batch_id"] == intent["batch_id"]), None)
        if batch is None or not changed <= set(batch["rule_ids"]):
            raise ValueError("實際修改規則超出批次授權範圍，拒絕自動恢復")
        state["changed_rules"] = sorted(set(state["changed_rules"]) | changed)
        state["mandatory_rules"] = sorted(set(state["mandatory_rules"]) | mandatory)
        remaining = ws.batch_blockers(batch, state["tasks"]) & ws.blocker_keys(current)
        if current["blocker_signature"] == state["observed_signature"]:
            raise ValueError("正式變更沒有改善權威診斷，需人工調查")
        if not remaining and intent["batch_id"] not in state["completed_batches"]:
            state["completed_batches"].append(intent["batch_id"])
        state["observed_diagnostic"] = current
        state["observed_signature"] = current["blocker_signature"]
        if ws.all_completed(state):
            if current.get("ready_for_second_pass"):
                state["phase"] = "sample"
            else:
                state["paused"] = True
                state["pause_reasons"] = ["批次修訂完成，但第一輪權威診斷仍有缺口"]
        result = {"batch_id": intent["batch_id"],
                  "original_blockers_remaining": len(remaining),
                  "phase": state["phase"]}
    elif intent["phase"] == "baseline":
        from second_pass_layers import worklist
        work = worklist(target)
        if not work.get("ready") or work.get("rules_total") != 70:
            raise ValueError("中斷後沒有合法的正式第二輪 Baseline／70 項計畫")
        state["phase"] = "second_pass"
        result = {"phase": "second_pass", "baseline_reconciled": True,
                  "rules_pending": work.get("rules_pending")}
    elif intent["phase"] == "second_pass":
        from second_pass_layers import worklist
        work = worklist(target)
        if not work.get("ready"):
            raise ValueError("第二輪正式 Baseline／工作清單驗證失敗")
        result = {"phase": "second_pass",
                  "rules_pending": work.get("rules_pending"),
                  "samples_pending": work.get("samples_pending")}
    else:
        raise ValueError("未知中斷階段")
    state["inflight"] = None
    state["last_evidence"] = evidence
    state["formal_fingerprints"] = current_fps
    ws.write_state(target / ws.STATE, state)
    return {"status": "reconciled", **result,
            "read_only_recovery": True,
            "note": "沒有重新執行 Stage／Integrate；以正式權威紀錄對帳結案"}


def finalize(target: Path) -> dict:
    """Final handoff is contingent on all the PREEXISTING official gates."""
    from second_pass_layers import worklist
    from review_queue import load_rules, build_queue
    from review_safety import safety_errors
    state = ws.load_state(target)
    ws.assert_state_current(target, state)
    if state["phase"] != "second_pass" or state.get("paused"):
        raise ValueError("完整 Wave 審查尚未進入正式第二輪結案")
    chain = state.get("sample_chain")
    if chain is not None:
        verify_sample_chain(chain)
    policy = state.get("sample_policy") or {}
    if set(policy.get("selected_rules") or []) != set(state.get("sample_records") or {}):
        raise ValueError("固定的人工抽樣尚未完成")
    work = worklist(target)
    if not (work.get("ready") and work.get("rules_total") == 70
            and work.get("rules_pending") == 0 and work.get("samples_pending") == 0):
        raise ValueError("70 條反向複核與固定來源抽樣尚未全部完成")
    assessment = ws.load_assessment(target)
    _, rules = load_rules()
    full = build_queue(assessment, rules, 10, source_root=target, compact=False)
    if not full.get("ready_for_report"):
        raise ValueError("正式非精簡佇列的 ready_for_report 尚未通過")
    issues = safety_errors(target, assessment)
    if issues:
        raise ValueError("正式安全守門未通過：" + "；".join(issues[:8]))
    report_root = target / REPORT_ROOT
    if (target / DELIVERY).exists():
        raise ValueError("既有交付紀錄不可覆寫；先人工核對")
    ws.ensure_stage_clean(target)
    proc = subprocess.run(
        [sys.executable, str(Path(__file__).with_name("complete_review.py")),
         "--target", str(target)],
        cwd=target, capture_output=True, text=True, timeout=1200, check=False,
    )
    if proc.returncode:
        raise ValueError("正式 complete_review.py 失敗（退出碼 " +
                         str(proc.returncode) + "）；不得宣稱交付成功")
    report = report_root / "report.json"
    date_text = assessment.get("assessment_date")
    if not isinstance(date_text, str):
        raise ValueError("正式報告日期缺失")
    html = report_root / ("CodeReview_" + date_text.replace("-", "") + ".html")
    if not report.is_file() or not html.is_file():
        raise ValueError("報告產生器沒有生成可交付的正式 HTML／JSON")
    result = {"schema_version": 1, "status": "validated",
              "reviewed_on": datetime.now(timezone.utc).isoformat(),
              "report_sha256": _file_sha(report), "html_sha256": _file_sha(html),
              "manifest_sha256": state["last_evidence"].get("manifest_sha256"),
              "independence": independence_metadata(),
              "report_path": report.relative_to(target).as_posix(),
              "html_path": html.relative_to(target).as_posix(),
              "note": "此交付旁錄不是正式 Journal 項目；L0 不代表獨立驗證"}
    ws.write_state(target / DELIVERY, result)
    return result
