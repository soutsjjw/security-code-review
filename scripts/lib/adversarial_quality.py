#!/usr/bin/env python3
"""第二輪反向複核品質守門：具體假設、重讀證據、矛盾裁決與跨規則模板偵測。

僅做可機械驗證的契約，不宣稱同一代理具備真正獨立盲審能力。
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any
import re

from review_decision import load_decision_matrix
from review_core import read_json as _read, snapshot_fingerprint
from adversarial_evidence import HIGH_RISK_RULES, SNAPSHOT, evidence_errors
from second_pass_layers import RESERVED

VERSION = 1
ATTACK_VECTORS = frozenset({
    "alternate_entry", "authorization_bypass", "identity_substitution",
    "expired_or_reused_credential", "configuration_override",
    "direct_storage_access", "untrusted_input", "output_encoding",
    "state_change", "exception_path", "dependency_injection",
    "third_party_boundary", "operational_override", "scope_challenge",
    "other_specific",
})
GENERIC_SURFACE = re.compile(
    r"^(?:(?:[a-z]{2}-\d{2})[-_])?"
    r"(?:adversarial[-_])?(?:attack|scenario|bypass|path|surface)"
    r"(?:[-_](?:path|surface|scenario))?[-_]\d+$", re.IGNORECASE,
)
REPLACEMENTS = [
    (re.compile(r"\b(?:AC|AU|IN|CR|EH|LG|DP|PD|BC|SI)-\d{2}\b", re.I), "<rule>"),
    (re.compile(r"\b[\w./\\-]+\.(?:cs|csproj|json|cshtml|razor|js|ts|vue)\b", re.I),
     "<file>"),
    (re.compile(r"\b\d+\b"), "<number>"),
]


def _normalized(text: str) -> str:
    for regex, substitute in REPLACEMENTS:
        text = regex.sub(substitute, text)
    return " ".join(text.casefold().split())


def _text_issues(value: Any, rid: str, name: str, min_length: int = 28) -> list[str]:
    if not isinstance(value, str) or len(value.strip()) < min_length:
        return [f"{rid}: 第二輪 {name} 缺少具體攻擊前提、控制效果或來源重查結果"]
    return []


def _location(proof: Any) -> tuple[str, int, int] | None:
    if (isinstance(proof, dict) and proof.get("kind") in {"source", "configuration"}
            and isinstance(proof.get("path"), str)
            and type(proof.get("line_start")) is int
            and type(proof.get("line_end")) is int):
        return proof["path"], proof["line_start"], proof["line_end"]
    return None


def _overlap(left: tuple[str, int, int], right: tuple[str, int, int]) -> bool:
    return left[0] == right[0] and left[1] <= right[2] and right[1] <= left[2]


def _locations(items: Any) -> set[tuple[str, int, int]]:
    """Finding 來源證據可沒有 kind，但仍須有實際路徑與合法行號。"""
    if not isinstance(items, list):
        return set()
    found: set[tuple[str, int, int]] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        loc = _location({**item, "kind": item.get("kind") or "source"})
        if loc is not None and loc[1] > 0 and loc[2] >= loc[1]:
            found.add(loc)
    return found


def quality_errors(target: Path, assessment: dict[str, Any], records: dict[str, Any],
                   baseline: dict[str, Any], decision_audits: dict[str, Any], *,
                   snapshot_override: dict | None = None) -> list[str]:
    """Q4 僅在新索引啟用；不修改任何 assessment、Finding 或第二輪資料。"""

    snapshot = snapshot_override if snapshot_override is not None else _read(target / SNAPSHOT, {})
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("source_hashes"), dict):
        return ["第二輪 Q4: 無有效來源快照"]
    if baseline.get("snapshot_fingerprint") != snapshot_fingerprint(snapshot):
        return ["第二輪 Q4: 第一輪與來源快照指紋不一致"]
    layered_mode = (isinstance(records.get(RESERVED), dict)
                    and isinstance(records[RESERVED].get("plan"), dict))
    matrix = load_decision_matrix()
    checks = assessment.get("checks", [])
    originals = baseline.get("checks", {})
    if not isinstance(checks, list) or not isinstance(originals, dict):
        return ["第二輪 Q4: 檢核結論或第一輪資料格式錯誤"]
    findings = {f.get("id"): f for f in assessment.get("findings", [])
                if isinstance(f, dict) and isinstance(f.get("id"), str)}
    known = set(snapshot["source_hashes"])
    errors: list[str] = []
    repeated: dict[tuple[str, str], set[str]] = defaultdict(set)
    reused_proofs: dict[tuple[str, int, int], set[str]] = defaultdict(set)
    reuse_justifications: dict[str, str] = {}

    for check in checks:
        if not isinstance(check, dict):
            continue
        rid = check.get("id")
        if rid not in matrix or (check.get("execution") or {}).get("state") != "completed":
            continue
        record, original = records.get(rid), originals.get(rid)
        if not isinstance(record, dict) or not isinstance(original, dict):
            continue  # 舊第二輪驗證已負責缺失及損毀紀錄。
        status = check.get("status")
        formal = check.get("evidence") if isinstance(check.get("evidence"), list) else []
        inspected = (check.get("execution") or {}).get("inspected_paths", [])
        inspected = set(p for p in inspected if isinstance(p, str)) \
            if isinstance(inspected, list) else set()
        audit = decision_audits.get(rid) if isinstance(decision_audits, dict) else None
        first_claim = original.get("decision_reason")
        review = record.get("reassessment")
        if not layered_mode and (not isinstance(first_claim, str) or len(first_claim.strip()) < 20):
            errors.append(f"{rid}: 第二輪 Q4 第一輪錨點缺少原始判定理由，須重建不可變錨點")
        if not isinstance(review, dict):
            errors.append(f"{rid}: 第二輪 Q4 缺少獨立於第一輪摘要的 reassessment")
        else:
            claim = review.get("first_pass_claim")
            if not layered_mode and (not isinstance(claim, str) or claim != first_claim):
                errors.append(f"{rid}: 第二輪 Q4 反向核對未引用第一輪固定的原始判定")
            if layered_mode:
                blind = record.get("blind_challenge")
                if not isinstance(blind, dict):
                    errors.append(f"{rid}: 第二輪分層複核缺少先於結論的 blind_challenge")
                else:
                    for field in ("factual_claim", "challenge_question", "initial_observation"):
                        errors.extend(_text_issues(blind.get(field), rid, "blind_challenge."+field))
                    factual = blind.get("factual_claim")
                    if (isinstance(first_claim, str) and isinstance(factual, str)
                            and first_claim.strip() and first_claim.strip() in factual):
                        errors.append(f"{rid}: 第二輪事實主張沿用第一輪判定措辭，存在錨定")
                    errors.extend(evidence_errors(
                        target, blind.get("evidence"), rid, "分層事實主張定位",
                        inspected, known, status, audit, formal))
            for field in ("challenge_question", "reinspection_summary", "conclusion_basis"):
                errors.extend(_text_issues(review.get(field), rid, field))
                if isinstance(review.get(field), str):
                    repeated[(field, _normalized(review[field]))].add(rid)
            if (isinstance(review.get("reinspection_summary"), str)
                    and isinstance(review.get("conclusion_basis"), str)
                    and _normalized(review["reinspection_summary"]) ==
                    _normalized(review["conclusion_basis"])):
                errors.append(f"{rid}: 第二輪 Q4 重查與裁決摘要完全相同，未展現新查證")
            proof = review.get("verification_evidence")
            errors.extend(evidence_errors(target, proof, rid, "Q4 重查來源", inspected,
                                           known, status, audit, formal))
            location = _location(proof)
            if location is not None:
                reused_proofs[location].add(rid)
                reuse_justifications[rid] = record.get("cross_rule_proof_justification", "")
        hypotheses = record.get("hypotheses")
        if not isinstance(hypotheses, list):
            continue
        vectors: set[str] = set()
        surfaces: set[str] = set()
        tactics: set[tuple[str, str]] = set()
        proofs: list[tuple[tuple[str, int, int] | None, tuple[str, int, int] | None]] = []
        for pos, item in enumerate(hypotheses):
            if not isinstance(item, dict):
                continue
            label = f"Q4 反例[{pos}]"
            vector = item.get("vector")
            if not isinstance(vector, str) or vector not in ATTACK_VECTORS:
                errors.append(f"{rid}: 第二輪 {label} 缺少具體攻擊向量 vector")
            else:
                vectors.add(vector)
                if vector == "other_specific":
                    errors.extend(_text_issues(item.get("vector_explanation"),
                                               rid, label + " 自訂攻擊向量"))
            surface = item.get("attack_surface")
            if isinstance(surface, str) and GENERIC_SURFACE.fullmatch(surface.strip()):
                errors.append(f"{rid}: 第二輪 {label} 使用制式 attack_surface，並非真實攻擊面")
            for field in ("attacker_precondition", "expected_violation",
                          "inspection_steps", "observed_behavior"):
                errors.extend(_text_issues(item.get(field), rid, f"{label}.{field}"))
                if isinstance(item.get(field), str):
                    repeated[(field, _normalized(item[field]))].add(rid)
            if isinstance(surface, str):
                surfaces.add(_normalized(surface))
            precondition, expected = item.get("attacker_precondition"), item.get("expected_violation")
            if isinstance(precondition, str) and isinstance(expected, str):
                tactic = (_normalized(precondition), _normalized(expected))
                if tactic in tactics:
                    errors.append(f"{rid}: 第二輪 {label} 與另一反例的攻擊前提及破壞目標相同")
                tactics.add(tactic)
            proof = item.get("inspection_evidence")
            errors.extend(evidence_errors(target, proof, rid, label+" 重新閱讀",
                                           inspected, known, status, audit, formal))
            evidence = item.get("evidence")
            proofs.append((_location(evidence), _location(proof)))
            # 一條反例應同時記錄「欲攻擊的地方」及「重新閱讀的控制／分支」。
            if (_location(evidence) is not None and _location(proof) is not None
                    and _location(evidence) == _location(proof)
                    and (not isinstance(item.get("same_line_explanation"), str)
                         or len(item["same_line_explanation"].strip()) < 30)):
                errors.append(f"{rid}: 第二輪 {label} 重查與攻擊證據同一行，須具體解釋該行如何同時證實兩者")
        if rid in HIGH_RISK_RULES and len(vectors) < 2:
            errors.append(f"{rid}: 第二輪 Q4 高風險規則須有至少兩種不同攻擊向量")
        if len(surfaces) < min(2, len(hypotheses)) and len(hypotheses) > 1:
            errors.append(f"{rid}: 第二輪 Q4 不同反例的攻擊面缺乏實質區別")
        if rid in HIGH_RISK_RULES and len(proofs) > 1 and len(set(proofs)) == 1:
            note = record.get("shared_evidence_justification")
            if not isinstance(note, str) or len(note.strip()) < 35:
                errors.append(f"{rid}: 第二輪 Q4 多個攻擊向量引用完全相同來源，須說明其控制交會點")
        if (record.get("outcome") == "corrected" and status == "fail"
                and original.get("status") != "fail"):
            confirmed = [_location(h.get("evidence")) for h in hypotheses
                         if isinstance(h, dict) and h.get("result") == "confirmed_vulnerability"]
            related = [f for fid in (check.get("finding_ids") or []) if isinstance(fid, str)
                       for f in [findings.get(fid)] if isinstance(f, dict)
                       and rid in (f.get("check_ids") or [])]
            if not any(_overlap(proof, evidence)
                       for proof in confirmed if proof is not None
                       for finding in related
                       for evidence in _locations(finding.get("evidence"))):
                errors.append(f"{rid}: 第二輪 Q4 修正為 Fail 的反例未連到本規則 Finding 來源")
        if record.get("outcome") == "corrected":
            contradictions = record.get("contradictions", [])
            if isinstance(contradictions, list):
                for pos, contradiction in enumerate(contradictions):
                    if not isinstance(contradiction, dict):
                        continue
                    errors.extend(_text_issues(contradiction.get("why_first_pass_missed"),
                                               rid, f"矛盾[{pos}] 原先漏判成因", 30))
                    errors.extend(_text_issues(contradiction.get("corrective_action"),
                                               rid, f"矛盾[{pos}] 修訂理由", 30))
    for location, rule_ids in reused_proofs.items():
        if len(rule_ids) >= 8:
            insufficient = [
                rid for rid in rule_ids
                if not isinstance(reuse_justifications.get(rid), str)
                or len(reuse_justifications[rid].strip()) < 35
            ]
            if insufficient:
                errors.append(
                    f"第二輪 Q4: {len(rule_ids)} 項規則的重查證據都指向"
                    f" {location[0]}:{location[1]}，需逐規則說明這個共用來源"
                    "與控制要求的真實關聯"
                )
    # 以規則編號、檔名、數字正規化後跨規則比對；避免 70 項套入同一個攻擊者模板。
    for (field, pattern), rule_ids in repeated.items():
        if len(rule_ids) >= 5 and len(pattern) >= 24:
            errors.append(
                f"第二輪 Q4: {len(rule_ids)} 項規則共用制式 {field} 敘述（"
                + "、".join(sorted(rule_ids)[:5]) + "），應逐規則重新查證"
            )
    return errors
