#!/usr/bin/env python3
"""為已 claim 的多代理分片產生精簡、自足的 Worker brief 檔案。

Worker 不必載入 SKILL.md 或完整規範文件：brief 只含派工 Prompt 模板、TASK_JSON、
70 項適用性索引、本分片候選規則的查核要點（共用部分只列一次）、按需讀取的標準文件
與壓縮後的結果 Schema。Worker 只觀察與回報證據，不做正式判定，因此不放裁決／第二輪指引。
Brief 寫在不屬正式報告的 analysis/multi-agent/briefs/，協調者只取得路徑與字數，
不必把內容讀進自己的上下文。
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import multi_agent_ledger as ml
import rule_guidance
from review_decision import load_decision_matrix

SKILL_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE_DOC = SKILL_ROOT / "docs/multi-agent-review.md"
SCHEMA = SKILL_ROOT / "schemas/multi-agent-worker-result.schema.json"
BRIEF_DIR = ml.ANALYSIS / "multi-agent/briefs"
_TEMPLATE_RE = re.compile(r"### 子代理派工 Prompt 模板\s+```text\n(.*?)```", re.S)
_TASK_LINE = re.compile(r"^TASK_JSON：.*$", re.M)


def prompt_template() -> str:
    """派工 Prompt 以 docs/multi-agent-review.md 的模板為唯一來源，避免兩份規範分歧。"""
    match = _TEMPLATE_RE.search(TEMPLATE_DOC.read_text(encoding="utf-8"))
    if not match or not _TASK_LINE.search(match.group(1)):
        raise ValueError("docs/multi-agent-review.md 缺少子代理派工 Prompt 模板或 TASK_JSON 行")
    return match.group(1).strip()


def _rules() -> list[dict]:
    rules = json.loads((SKILL_ROOT / "rules.json").read_text(encoding="utf-8"))["rules"]
    if len(rules) != 70:
        raise ValueError("規則主檔必須包含 70 項")
    return rules


def _one_line(text: str) -> str:
    return " ".join(str(text).split())


def candidate_rule_ids(task: dict) -> list[str]:
    ids = {rid for part in task.get("assigned_paths", []) if isinstance(part, dict)
           for rid in part.get("candidate_rule_ids", []) if isinstance(rid, str)}
    return sorted(ids)


def build_brief(task: dict) -> str:
    """回傳 Markdown brief；只依 TASK_JSON 與 Skill 自身規範產生，不讀受測來源。"""
    rules = _rules()
    matrix = load_decision_matrix()
    by_id = {r["id"]: r for r in rules}
    candidates = [rid for rid in candidate_rule_ids(task) if rid in by_id]
    shared_control = rule_guidance.shared_guidance()["control_effectiveness_guidance"]
    maps = rule_guidance.standard_maps(rules) if candidates else {}
    task_json = json.dumps(task, ensure_ascii=False, separators=(",", ":"))
    lines = [_TASK_LINE.sub(lambda _: "TASK_JSON：" + task_json, prompt_template()), ""]

    lines += ["## 十類 70 項適用性索引",
              "對每個檔案依此做 category_screening；格式：ID 標題｜須評估｜可不適用。", ""]
    for rule in rules:
        applicability = rule.get("applicability", {})
        lines.append(f"- {rule['id']} {rule['title']}｜{_one_line(applicability.get('must_assess_when', ''))}"
                     f"｜{_one_line(applicability.get('may_be_not_applicable_when', ''))}")

    lines += ["", "## 本分片候選規則查核要點",
              "候選來自索引，只是定位線索；仍須逐檔閱讀。控制鏈證據共用要求："
              + json.dumps(shared_control, ensure_ascii=False, separators=(",", ":")), ""]
    documents: list[str] = []
    for rid in candidates:
        rule, decision = by_id[rid], matrix[rid]
        specific = rule_guidance.specific_guidance(rid, {"control_effectiveness_guidance": shared_control})
        scenarios = specific["control_effectiveness_guidance"].get("required_scenarios", [])
        inspection = rule.get("inspection", {})
        lines.append(f"### {rid} {rule['title']}")
        lines.append(f"- 查核方法：{_one_line(inspection.get('verification_method', ''))}")
        targets = inspection.get("search_targets") or []
        if targets:
            lines.append("- 搜尋目標：" + "、".join(map(str, targets)))
        lines.append(f"- 預期證據：{_one_line(decision.get('expected_evidence', ''))}")
        if scenarios:
            lines.append("- 必查繞過情境：" + "、".join(scenarios))
        item = {field: mapping.get(rid) for field, mapping in maps.items()}
        documents += rule_guidance.standard_documents(item)
    if not candidates:
        lines.append("（本分片沒有索引候選規則；仍須依適用性索引逐檔篩選十類。）")

    documents = list(dict.fromkeys(documents))
    lines += ["", "## 按需讀取的標準文件",
              "只在判斷候選規則的適用性或證據不確定時讀取；不必預先全部載入。"]
    lines += [f"- {(SKILL_ROOT / doc).as_posix()}" for doc in documents] or ["- （無）"]
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    lines += ["", "## 結果 JSON Schema（壓縮）",
              json.dumps(schema, ensure_ascii=False, separators=(",", ":")), ""]
    return "\n".join(lines)


def write_brief(root: Path, task_id: str) -> dict:
    """只為狀態為 running（已 claim、含 challenge_lines）的分片產生 brief。"""
    state, _ = ml.active_plan(root)
    row = state.get("tasks", {}).get(task_id)
    if row is None:
        raise ValueError("未知 task_id")
    if row.get("status") not in {"running", "followup_running"}:
        raise ValueError("只能為已 claim 的分片產生 brief；請先執行 --claim 或 --claim-batch")
    brief = build_brief(row["task"])
    directory = root / BRIEF_DIR
    directory.mkdir(parents=True, exist_ok=True)
    if directory.is_symlink():
        raise ValueError("brief 目錄不可為符號連結")
    path = directory / f"{task_id}.md"
    path.write_bytes(brief.encode("utf-8"))
    return {"task_id": task_id, "brief_path": path.as_posix(), "brief_chars": len(brief),
            "candidate_rule_ids": candidate_rule_ids(row["task"]),
            "note": "將 brief_path 交給子代理讀取即可；協調者不必讀入 brief 內容"}
