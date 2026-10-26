#!/usr/bin/env python3
"""唯讀批次來源提示；不建立 file_reviews、不宣稱已閱讀或完成任何規則。"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from analysis_candidates import candidate_hits
from review_queue import REPORT_RELATIVE
from source_coverage import provisional_source_coverage
from source_reader import read_source_text, source_digest

INDEX = Path("reports/security-code-review/analysis/structure-index.json")


def skeleton(target: Path, *, batch_size: int = 30, workers: int = 1,
             worker_id: int = 0, offset: int = 0, include_existing: bool = False,
             requested_paths: list[str] | None = None) -> dict:
    """工作分片純屬讀取分工。每個來源檔仍須由 Agent 真實閱讀。"""
    if not 1 <= batch_size <= 200:
        raise ValueError("batch_size 必須介於 1～200")
    if not 1 <= workers <= 32 or not 0 <= worker_id < workers:
        raise ValueError("workers 必須介於 1～32，worker_id 須小於 workers")
    if offset < 0:
        raise ValueError("offset 不可為負")
    root = target.resolve()
    report = root / REPORT_RELATIVE
    assessment = json.loads((report / "assessment.json").read_text(encoding="utf-8"))
    index = json.loads((root / INDEX).read_text(encoding="utf-8"))
    snapshot = json.loads((report / "analysis/review-snapshot.json").read_text(encoding="utf-8"))
    hashes = snapshot.get("source_hashes")
    if not isinstance(hashes, dict) or hashes != index.get("source_hashes"):
        raise ValueError("來源快照與索引不同；請重建結構索引，不得使用過期提示")
    from source_coverage import expected_paths
    from scope_inventory import relative_path
    exclusions = [
        relative_path(root, row["path"], root_allowed=True)
        for row in (assessment.get("scope_details") or {}).get("excluded_paths", [])
    ]
    current = expected_paths(root, exclusions)
    if current != set(hashes):
        raise ValueError("受測來源清單已異動，請重新建立來源快照")
    if requested_paths:
        paths = sorted(set(requested_paths))
        if any(path not in current for path in paths):
            raise ValueError("指定路徑不在應審查來源清單中")
    elif include_existing:
        paths = sorted(current)
    else:
        paths = provisional_source_coverage(assessment, root)["missing_source_paths"]
    # SHA256 對路徑取模，新增或減少其它路徑不會改變分片歸屬。
    shard = [path for path in paths
             if int(hashlib.sha256(path.encode("utf-8")).hexdigest(), 16) % workers == worker_id]
    rows = []
    page = shard[offset:offset + batch_size]
    for relative in page:
        path = (root / relative).resolve()
        if not path.is_relative_to(root) or not path.is_file() or path.is_symlink():
            raise ValueError("來源路徑無效、符號連結或超出受測範圍")
        raw = path.read_bytes()
        digest = source_digest(raw)
        if digest != hashes[relative]:
            raise ValueError(f"{relative}: SHA256 與來源快照不同，拒絕使用過期候選")
        content, encoding = read_source_text(path, raw=raw)
        roslyn = (index.get("roslyn_files") or {}).get(relative, {})
        # 只傳定位欄位；完整宣告／簽章保留在 structure-index.json 按需查詢。
        methods = roslyn.get("methods", [])
        symbols = [{key: item[key] for key in
                    ("name", "line", "end_line", "containing_type") if key in item}
                   for item in methods if isinstance(item, dict)]
        hits = (index.get("rule_candidates") or {}).get(relative)
        if hits is None:
            hits = candidate_hits(relative, content)
        calls = (index.get("cross_file_call_hints") or {}).get(relative, [])
        rows.append({
            "path": relative,
            "sha256": digest,
            "encoding": encoding,
            "line_count": len(content.splitlines()),
            "rule_candidates": hits,
            "roslyn_methods": symbols,
            "roslyn_method_count": len(methods),
            "cross_file_callsite_ids": [call["id"] for call in calls if "id" in call],
            "must_read_source": True,
        })
    return {
        "mode": "read_only_work_hints", "source_snapshot_checked": True,
        "worker_id": worker_id, "workers": workers, "offset": offset,
        "next_offset": offset + len(rows) if offset + len(rows) < len(shard) else None,
        "remaining_in_shard": max(0, len(shard) - offset - len(rows)),
        "files": rows, "ready_for_report": False,
        "required_agent_fields": ["summary", "methods", "category_screening",
                                  "rule_reviews", "candidate_exclusions"],
        "notice": "此工具不產生安全判定；每檔須完整閱讀，並由主代理依正式 Schema 寫入證據。",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=Path.cwd())
    parser.add_argument("--batch-size", type=int, default=30)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--worker-id", type=int, default=0)
    parser.add_argument("--offset", type=int, default=0,
                        help="此 worker 的唯讀批次位移，用於分頁，不依賴正式寫入進度")
    parser.add_argument("--include-existing", action="store_true")
    parser.add_argument("--path", action="append", dest="paths",
                        help="可重複指定需唯讀分析的來源相對路徑")
    args = parser.parse_args()
    try:
        result = skeleton(args.target, batch_size=args.batch_size,
                          workers=args.workers, worker_id=args.worker_id,
                          offset=args.offset,
                          include_existing=args.include_existing,
                          requested_paths=args.paths)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR: 無法建立來源工作提示：{exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
