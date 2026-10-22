#!/usr/bin/env python3
"""僅建立可重用的結構索引；絕不填寫審查結論或自動完成規則。"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from analysis_adapters import ADAPTERS, probe_codegraph, probe_roslyn
from analysis_candidates import DOTNET_EXTENSIONS, candidate_hits
from source_reader import read_source_text
from scope_inventory import EXCLUDED_DIRS, _default_rule, relative_path
from source_coverage import SOURCE_FILENAMES, SOURCE_SUFFIXES

INDEX_VERSION = 1
ROSLYN_VERSION = "roslyn-syntax-v1"
CANDIDATE_VERSION = 1
SKILL_ROOT = Path(__file__).resolve().parents[1]
INDEX_NAME = "reports/security-code-review/analysis/structure-index.json"


def source_files(root: Path, excluded: list[str] | None = None) -> dict[str, str]:
    """和既有來源覆蓋清單共用副檔名與排除原則，雜湊由本機計算。"""
    excluded = excluded or []
    files: dict[str, str] = {}
    for current, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS and not d.startswith(".codegraph-") and not (Path(current) / d).is_symlink()
                  and not _default_rule((Path(current) / d).relative_to(root).as_posix())
                  and not any((Path(current) / d).relative_to(root).as_posix() == p or
                              (Path(current) / d).relative_to(root).as_posix().startswith(p.rstrip("/") + "/")
                              for p in excluded)]
        for name in names:
            path = Path(current) / name
            if not path.is_file() or path.is_symlink():
                continue
            rel = path.relative_to(root).as_posix()
            if _default_rule(rel) or any(rel == p or rel.startswith(p.rstrip("/") + "/") for p in excluded):
                continue
            if path.suffix.lower() in SOURCE_SUFFIXES or name in SOURCE_FILENAMES or path.suffix.lower() == ".vue":
                files[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return dict(sorted(files.items()))


def _run_roslyn(root: Path, pending: list[str], probe: dict) -> tuple[dict, list[str]]:
    """在暫存目錄編譯 SDK 內建 Roslyn 工具，不修改受測專案或安裝 NuGet 套件。"""
    if not pending:
        return {}, []
    if not probe["available"]:
        return {}, ["Roslyn 無法使用；需由 Agent 繼續原始碼分析"]
    with tempfile.TemporaryDirectory(prefix="security-review-roslyn-") as tmp:
        work = Path(tmp)
        source = SKILL_ROOT / "tools/roslyn-indexer"
        project = (source / "roslyn-indexer.csproj").read_text(encoding="utf-8")
        project = project.replace("net8.0", probe["target_framework"])
        (work / "roslyn-indexer.csproj").write_text(project, encoding="utf-8")
        shutil.copy2(source / "Program.cs", work / "Program.cs")
        manifest = work / "manifest.json"
        manifest.write_text(json.dumps(pending, ensure_ascii=False), encoding="utf-8")
        env = dict(os.environ, DOTNET_CLI_TELEMETRY_OPTOUT="1", DOTNET_NOLOGO="1",
                   DOTNET_SKIP_FIRST_TIME_EXPERIENCE="1")
        try:
            result = subprocess.run([probe["executable"], "run", "--project", str(work / "roslyn-indexer.csproj"),
                                     "--configuration", "Release", "--", str(root), str(manifest)],
                                    capture_output=True, text=True, cwd=work, env=env,
                                    timeout=180, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {}, [f"Roslyn 執行失敗：{type(exc).__name__}"]
        line = next((x.removeprefix("SCROSLYN_JSON:") for x in result.stdout.splitlines()
                     if x.startswith("SCROSLYN_JSON:")), None)
        if not line:
            return {}, ["Roslyn 無法輸出有效索引（SDK 或相依套件可能未就緒）"]
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            return {}, ["Roslyn 索引 JSON 無法解析"]
        data = {r["path"]: r for r in payload.get("files", []) if isinstance(r, dict) and "path" in r}
        return data, payload.get("errors", [])


def prepare(root: Path, mode: str = "full") -> dict:
    root = root.resolve()
    if not root.is_dir() or root == SKILL_ROOT or SKILL_ROOT in root.parents:
        raise ValueError("受測專案路徑不存在或指向 Skill 本身")
    adapter = ADAPTERS[0]  # 第一階段僅啟用現代 .NET；往後可由 registry 選擇。
    detection = adapter.detect(root)
    report_dir = root / "reports/security-code-review"
    assessment_path = report_dir / "assessment.json"
    excluded: list[str] = []
    if assessment_path.is_file():
        assessment = json.loads(assessment_path.read_text(encoding="utf-8"))
        for row in (assessment.get("scope_details") or {}).get("excluded_paths", []):
            if isinstance(row, dict) and "path" in row:
                path = relative_path(root, row["path"], root_allowed=True)
                if path == ".":
                    raise ValueError("不可排除整個受測專案")
                excluded.append(path)
    source = source_files(root, excluded)
    has_vue = any(p.endswith(".vue") for p in source)
    if not detection["supported"] or has_vue:
        raise ValueError("第一階段僅支援 .NET Core／現代 .NET 專案；遇到傳統 .NET Framework、Vue、"
                         "未辨識 TFM 或混合專案須停止，不可宣稱完整掃描。"
                         f" projects={detection['projects'][:5]}, vue={has_vue}")
    codegraph = probe_codegraph(root)
    roslyn = probe_roslyn()
    index = root / INDEX_NAME
    previous = {}
    if mode == "incremental" and index.is_file():
        try:
            previous = json.loads(index.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            previous = {}
    compatible = (previous.get("schema_version") == INDEX_VERSION and
                  previous.get("adapter") == adapter.name and
                  previous.get("roslyn_version") == ROSLYN_VERSION and
                  previous.get("sdk_version") == roslyn.get("sdk_version"))
    old_hashes = previous.get("source_hashes", {}) if compatible else {}
    if not isinstance(old_hashes, dict):
        old_hashes = {}
    changed = sorted(p for p, sha in source.items() if old_hashes.get(p) != sha)
    removed = sorted(set(old_hashes) - set(source))
    csharp = [p for p in source if p.endswith(".cs")]
    old_entries = previous.get("roslyn_files", {}) if compatible else {}
    if not isinstance(old_entries, dict):
        old_entries = {}
    # 結構快取僅重用與來源 SHA256 相同的候選訊號，從不重用安全結論。
    old_candidates = (previous.get("rule_candidates", {})
                      if compatible and previous.get("candidate_version") == CANDIDATE_VERSION else {})
    if not isinstance(old_candidates, dict):
        old_candidates = {}
    rule_candidates: dict[str, list[dict]] = {}
    candidate_reused = 0
    for path in source:
        if Path(path).suffix.lower() not in DOTNET_EXTENSIONS:
            continue
        if old_hashes.get(path) == source[path] and path in old_candidates:
            rule_candidates[path] = old_candidates[path]
            candidate_reused += 1
        else:
            rule_candidates[path] = candidate_hits(path, read_source_text(root / path)[0])
    reused = {p: old_entries[p] for p in csharp if p not in changed and p in old_entries}
    pending = [p for p in csharp if p not in reused]
    parsed, errors = _run_roslyn(root, pending, roslyn)
    indexed = {**reused, **parsed}
    # 變更的呼叫端/組態可能影響未變動來源；沒有受驗證依賴閉包前採保守重審。
    recheck = sorted(source) if changed or removed or not compatible or mode == "full" else []
    payload = {
        "schema_version": INDEX_VERSION, "adapter": adapter.name, "mode": mode,
        "roslyn_version": ROSLYN_VERSION, "sdk_version": roslyn.get("sdk_version"),
        "candidate_version": CANDIDATE_VERSION, "rule_candidates": rule_candidates,
        "source_hashes": source, "roslyn_files": indexed,
        "changed_paths": changed, "removed_paths": removed, "recheck_paths": recheck,
        "codegraph": codegraph, "roslyn": {k: v for k, v in roslyn.items() if k != "executable"},
        "roslyn_errors": errors,
        "warning": "結構索引及快取不能代替安全審查證據；不得直接寫入 completed/pass/na 或繼承失效的 Finding。"
    }
    index.parent.mkdir(parents=True, exist_ok=True)
    temp_index = index.with_suffix(".tmp")
    temp_index.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp_index.replace(index)
    return {
        "adapter": adapter.name, "projects": detection["projects"],
        "source_file_count": len(source), "csharp_file_count": len(csharp),
        "changed_file_count": len(changed), "changed_paths": changed[:30],
        "removed_file_count": len(removed), "recheck_file_count": len(recheck),
        "recheck_paths": recheck[:30], "roslyn_indexed_count": len(indexed),
        "roslyn_reused_count": len(reused), "roslyn_errors": errors[:10],
        "candidate_file_count": sum(bool(hits) for hits in rule_candidates.values()),
        "candidate_link_count": sum(len(hits) for hits in rule_candidates.values()),
        "candidate_reused_count": candidate_reused,
        "candidate_examples": [
            {"path": path, "rule_ids": [hit["rule_id"] for hit in hits]}
            for path, hits in rule_candidates.items() if hits
        ][:12],
        "codegraph": codegraph, "roslyn": payload["roslyn"],
        "index_path": INDEX_NAME, "complete_security_review": False,
        "notice": "必須繼續執行 70 項實際檢核、逐檔取證與原有完整性驗證。"
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="準備 .NET 結構索引（不執行或完成安全審查）")
    parser.add_argument("--target", type=Path, default=Path.cwd())
    parser.add_argument("--mode", choices=("full", "incremental"), default="full")
    args = parser.parse_args()
    try:
        data = prepare(args.target, args.mode)
    except (ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(data, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
