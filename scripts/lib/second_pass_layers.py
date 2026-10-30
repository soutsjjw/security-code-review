#!/usr/bin/env python3
"""分層式第二輪：只由已封存的第一輪快照產生工作清單；不掃描整棵來源樹。"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any

from review_core import ANALYSIS_ROOT, read_json as _read
from review_decision import is_weak_source_evidence

VERSION = 1
RESERVED = "__layered__"
RELATIVE = ANALYSIS_ROOT
RISK_PATTERNS = (
    ("entry", re.compile(r"controller|endpoint|middleware|handler|route|api", re.I)),
    ("authorization", re.compile(r"auth|identity|permission|role|policy|access", re.I)),
    ("configuration", re.compile(r"config|settings|startup|program\\.cs|\.props|\.targets", re.I)),
    ("input", re.compile(r"input|request|upload|parser|deserial|binding|validation", re.I)),
    ("error", re.compile(r"exception|error|filter|fallback", re.I)),
)


def _hash(data: Any) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=False,
                                      separators=(",", ":")).encode("utf-8")).hexdigest()


def _anchors(check: dict, known: set[str]) -> list[dict]:
    anchors: list[dict] = []
    for proof in check.get("evidence") or []:
        if not isinstance(proof, dict):
            continue
        path = proof.get("path")
        if path not in known:
            continue
        start, end = proof.get("line_start"), proof.get("line_end")
        if type(start) is int and type(end) is int and start > 0 and end >= start:
            anchor = {"path": path, "line_start": start, "line_end": end}
            if anchor not in anchors:
                anchors.append(anchor)
    return anchors[:12]


def build_plan(assessment: dict, baseline: dict, snapshot: dict, *,
               sample_limit: int = 24, sample_rate: float = 0.10,
               rule_batch: int = 8, path_batch: int = 16,
               sample_batch: int = 4) -> dict:
    """輸出不含判定、信心及 decision_reason 的唯讀工作輸入。"""
    if not (1 <= sample_limit <= 100 and 0 < sample_rate <= 0.3
            and 1 <= rule_batch <= 10 and 1 <= path_batch <= 32
            and 1 <= sample_batch <= 8):
        raise ValueError("第二輪預算超出允許的界線")
    sources = snapshot.get("source_hashes")
    checks = assessment.get("checks")
    if not isinstance(sources, dict) or not isinstance(checks, list) or len(checks) != 70:
        raise ValueError("建立第二輪計畫需要 70 項及有效的來源快照")
    known = set(sources)
    work: dict[str, dict] = {}
    referenced: set[str] = set()
    for check in sorted(checks, key=lambda c: c["id"]):
        anchors = _anchors(check, known)
        referenced.update(a["path"] for a in anchors)
        inspected = [p for p in (check.get("execution") or {}).get("inspected_paths", [])
                     if p in known]
        # 無正式定位證據時以候選路徑提示，不假裝已重查，須人工追蹤。
        work[check["id"]] = {
            "evidence_anchors": anchors,
            "candidate_paths": sorted(set(inspected))[:3] if not anchors else [],
            "needs_new_anchor": not bool(anchors),
        }
    seed = _hash({"snapshot": baseline["snapshot_fingerprint"],
                  "first_pass": {k: v["digest"] for k, v in baseline["checks"].items()}})
    candidates: list[tuple[int, str, str, list[str]]] = []
    for path in known - referenced:
        signals = [label for label, regex in RISK_PATTERNS if regex.search(path)]
        if not signals:
            continue
        tie = hashlib.sha256((seed + ":" + path).encode("utf-8")).hexdigest()
        candidates.append((-len(signals), tie, path, signals))
    candidates.sort()
    count = min(sample_limit, math.ceil(len(candidates) * sample_rate))
    sampled = [{"path": p, "risk_signals": signals} for _, _, p, signals
               in candidates[:count]]
    return {
        "version": VERSION, "mode": "targeted_adversarial_plus_independent_sample",
        "snapshot_fingerprint": baseline["snapshot_fingerprint"],
        "baseline_digest": _hash(baseline),
        "sampling": sampled, "sampling_candidate_count": len(candidates),
        "sample_policy": {"limit": sample_limit, "rate": sample_rate,
                          "selection": "risk-signals-and-snapshot-seeded-order"},
        "budgets": {"max_rules_per_batch": rule_batch,
                    "max_paths_per_batch": path_batch,
                    "max_samples_per_batch": sample_batch,
                    "token_hint_per_batch": 30000},
        "rules": work,
        "limitations": "同一主代理不具備真正盲審；若必要路徑超出清單須有界延伸並分批續跑",
    }


def record_errors(target: Path, path: str, record: Any, plan: dict,
                  snapshot: dict, assessment: dict) -> list[str]:
    selected = {x["path"] for x in plan.get("sampling", [])}
    if path not in selected:
        return [f"第二輪抽樣：{path} 不在固定獨立樣本清單"]
    if not isinstance(record, dict):
        return [f"第二輪抽樣：{path} 必須提供紀錄物件"]
    outcome = record.get("outcome")
    if outcome not in {"no_new_issue", "confirmed_vulnerability", "not_applicable"}:
        return [f"第二輪抽樣：{path} 必須明確裁決，不能將未查完視為通過"]
    summary = record.get("inspection_summary")
    if not isinstance(summary, str) or len(summary.strip()) < 28:
        return [f"第二輪抽樣：{path} 缺少重新閱讀獨立路徑的具體說明"]
    proof = record.get("evidence")
    if not isinstance(proof, dict) or proof.get("kind") not in {"source", "configuration"} or proof.get("path") != path:
        return [f"第二輪抽樣：{path} 必須引用抽樣檔案本身的來源證據"]
    start, end = proof.get("line_start"), proof.get("line_end")
    if type(start) is not int or type(end) is not int or start <= 0 or end < start:
        return [f"第二輪抽樣：{path} 的行號不合法"]
    if path not in snapshot.get("source_hashes", {}):
        return [f"第二輪抽樣：{path} 已不在封存來源"]
    from source_reader import read_source_text
    candidate = (target.resolve() / path).resolve()
    if not candidate.is_relative_to(target.resolve()) or not candidate.is_file():
        return [f"第二輪抽樣：{path} 來源不存在或路徑逃逸"]
    try:
        text, _ = read_source_text(candidate)
    except (OSError, UnicodeError) as exc:
        return [f"第二輪抽樣：{path} 不能讀取來源：{type(exc).__name__}"]
    if end > len(text.splitlines()):
        return [f"第二輪抽樣：{path} 超出實際來源行號"]
    if is_weak_source_evidence(proof, target) is True:
        return [f"第二輪抽樣：{path} 僅有註解、宣告或 using，不能作為證據"]
    if outcome == "confirmed_vulnerability":
        finding_id = record.get("finding_id")
        finding = next((f for f in assessment.get("findings", [])
                        if f.get("id") == finding_id), None)
        if not isinstance(finding, dict):
            return [f"第二輪抽樣：{path} 發現弱點但缺少正式 Finding"]
        if not any(e.get("path") == path for e in finding.get("evidence", [])
                   if isinstance(e, dict)):
            return [f"第二輪抽樣：{path} Finding 沒有引用相同受測路徑"]
        checks = assessment.get("checks")
        if not isinstance(checks, list) or not any(
            isinstance(c, dict) and c.get("status") == "fail"
            and finding_id in (c.get("finding_ids") or [])
            and c.get("id") in (finding.get("check_ids") or [])
            for c in checks
        ):
            return [f"第二輪抽樣：{path} 缺少關聯的正式 Fail 規則，不能只有 Finding"]
    elif record.get("finding_id"):
        return [f"第二輪抽樣：{path} 未確認弱點卻填入 Finding"]
    return []


def layered_errors(target: Path, assessment: dict, baseline: dict,
                   snapshot: dict, reviews: dict) -> list[str]:
    layer = reviews.get(RESERVED)
    if layer is None:
        return []  # 既有版本的不可變 baseline 不強制遷移。
    if not isinstance(layer, dict) or not isinstance(layer.get("plan"), dict):
        return ["第二輪：分層計畫損毀"]
    plan = layer["plan"]
    # 完整性由既有 Journal/Manifest 維護；不因第二輪合法修訂正式 checks
    # 而改寫原本的取樣清單，避免讓既有樣本悄悄消失。
    chosen_rows = plan.get("sampling")
    planned_rules = plan.get("rules")
    if (plan.get("version") != VERSION
            or plan.get("snapshot_fingerprint") != baseline.get("snapshot_fingerprint")
            or plan.get("baseline_digest") != _hash(baseline)
            or not isinstance(chosen_rows, list)
            or not isinstance(planned_rules, dict)
            or set(planned_rules) != set(baseline.get("checks", {}))
            or any(not isinstance(row, dict) or row.get("path") not in snapshot.get("source_hashes", {})
                   for row in chosen_rows)):
        return ["第二輪：固定抽樣計畫與第一輪不可變錨點不一致"]
    samples = layer.get("samples", {})
    if not isinstance(samples, dict):
        return ["第二輪：抽樣紀錄格式錯誤"]
    chosen = {x["path"] for x in plan["sampling"]}
    errors = [f"第二輪抽樣：{p} 不在計畫內" for p in samples if p not in chosen]
    for path in sorted(chosen):
        if path not in samples:
            errors.append(f"第二輪抽樣：{path} 尚未完成，不能正式結案")
        else:
            errors.extend(record_errors(target, path, samples[path], plan, snapshot, assessment))
    return errors


def worklist(target: Path) -> dict:
    baseline = _read(target / RELATIVE / "first-pass-baseline.json", {})
    reviews = _read(target / RELATIVE / "adversarial-reviews.json", {})
    layer = reviews.get(RESERVED) if isinstance(reviews, dict) else None
    if not isinstance(layer, dict) or not isinstance(layer.get("plan"), dict):
        return {"ready": False, "instruction": "先執行 --begin-second-pass，舊版錨點須人工決定是否重啟"}
    plan = layer["plan"]
    budgets = plan["budgets"]
    done = {k for k, v in reviews.items() if k != RESERVED and isinstance(v, dict)
            and v.get("baseline_digest") == baseline.get("checks", {}).get(k, {}).get("digest")
            and isinstance(v.get("final_digest"), str) and len(v["final_digest"]) == 64
            and isinstance(v.get("hypotheses"), list) and bool(v["hypotheses"])
            and v.get("open_issues") == []}
    pending = [rid for rid in sorted(plan["rules"]) if rid not in done]
    tasks = []
    paths: set[str] = set()
    for rid in pending:
        item = plan["rules"][rid]
        suggestions = [a["path"] for a in item["evidence_anchors"]] or item["candidate_paths"]
        more = set(suggestions) - paths
        if tasks and (len(tasks) >= budgets["max_rules_per_batch"]
                      or len(paths) + len(more) > budgets["max_paths_per_batch"]):
            break
        paths.update(suggestions)
        tasks.append({"rule_id": rid, **item})
    completed_samples = layer.get("samples", {})
    sample_pending = [s for s in plan["sampling"] if s["path"] not in completed_samples]
    return {"ready": True, "rules_total": len(plan["rules"]), "rules_pending": len(pending),
            "rule_tasks": tasks, "targeted_paths": sorted(paths),
            "samples_total": len(plan["sampling"]),
            "samples_pending": len(sample_pending),
            "sample_tasks": sample_pending[:budgets["max_samples_per_batch"]],
            "budgets": budgets, "paused": False,
            "instruction": "本批結束後重新查詢；超出讀檔或 token 預算時儲存已核實證據並暫停，不能當作 completed。"}


def main() -> int:
    parser = argparse.ArgumentParser(description="第二輪唯讀分層工作清單")
    parser.add_argument("--target", type=Path, default=Path.cwd())
    args = parser.parse_args()
    print(json.dumps(worklist(args.target.resolve()), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
