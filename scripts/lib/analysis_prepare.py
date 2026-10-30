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
from review_relationships import build_relationships
from review_snapshot import initialize_snapshot, source_files
from scope_paths import relative_path
from review_core import ANALYSIS_ROOT, REPORT_ROOT, write_json_atomic

INDEX_VERSION = 10
ROSLYN_VERSION = "roslyn-symbol-candidates-v4"
CANDIDATE_VERSION = 2
SKILL_ROOT = Path(__file__).resolve().parents[2]
INDEX_NAME = (ANALYSIS_ROOT / "structure-index.json").as_posix()


def _private_mkdir(path: Path, *, windows: bool | None = None) -> None:
    """POSIX 以 0o700 限制快取僅本人可用；Windows 改依家目錄繼承的 ACL。

    Python 3.13+ 在 Windows 的 mode=0o700 會套用僅建立者可存取的 ACL，sandbox 等其他
    身分建立的快取之後連使用者本人都無法讀取或刪除，而家目錄預設 ACL 已限於本人、SYSTEM 與管理員。
    """
    if windows is None:
        windows = os.name == "nt"
    if windows:
        path.mkdir(parents=True, exist_ok=True)
    else:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)


def _run_roslyn(root: Path, pending: list[str], probe: dict, *, no_cache: bool = False) -> tuple[dict, list[str]]:
    """Use exactly the SDK shipping the Roslyn DLLs; cache permission fails open to scratch,
    never to unverified symbol evidence."""
    try:
        return _run_roslyn_work(root, pending, probe, no_cache=no_cache)
    except (OSError, PermissionError) as exc:
        if not no_cache and os.environ.get("SECURITY_CODE_REVIEW_ROSLYN_CACHE", "1") != "0":
            data, warnings = _run_roslyn(root, pending, probe, no_cache=True)
            return data, ["Roslyn 快取／暫存權限不足，已改用隔離暫存：" + type(exc).__name__, *warnings]
        return {}, ["Roslyn 無法建立可寫入的工具暫存目錄：" + type(exc).__name__]


def _run_roslyn_work(root: Path, pending: list[str], probe: dict, *,
                     no_cache: bool = False) -> tuple[dict, list[str]]:
    if not pending:
        return {}, []
    if not probe["available"]:
        return {}, ["Roslyn 無法使用；需由 Agent 繼續原始碼分析"]
    source = SKILL_ROOT / "tools/roslyn-indexer"
    project = (source / "roslyn-indexer.csproj").read_text(encoding="utf-8")
    program = (source / "Program.cs").read_bytes()
    fingerprint = hashlib.sha256(
        project.encode("utf-8") + program
        + str(probe.get("sdk_version")).encode("utf-8")
        + str(probe["target_framework"]).encode("utf-8")
        + str(probe["executable"]).encode("utf-8")
    ).hexdigest()
    use_cache = not no_cache and os.environ.get("SECURITY_CODE_REVIEW_ROSLYN_CACHE", "1") != "0"
    if use_cache:
        cache = Path.home() / ".cache" / "security-code-review" / "roslyn" / fingerprint
        # 本機快取不得經 symlink 執行任意替換的 binary；由使用者可關閉快取。
        if any(node.is_symlink() for node in (cache, cache.parent, cache.parent.parent)):
            return {}, ["Roslyn 快取路徑包含 symbolic link，請關閉快取後重試"]
    env = dict(os.environ, DOTNET_CLI_TELEMETRY_OPTOUT="1", DOTNET_NOLOGO="1",
               DOTNET_SKIP_FIRST_TIME_EXPERIENCE="1")
    with tempfile.TemporaryDirectory(prefix="security-review-roslyn-") as tmp:
        scratch = Path(tmp)
        # dotnet --version and dotnet build MUST use the same isolated cwd:
        # using the audited repo/global.json for one and cache for the other
        # can select SDK 8 then compile against SDK 10 Roslyn (CS1705).
        sdk_check = subprocess.run(
            [probe["executable"], "--version"], cwd=scratch,
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=10, check=False)
        if sdk_check.returncode != 0 or sdk_check.stdout.strip() != probe.get("sdk_version"):
            return {}, ["Roslyn SDK 版本在探測與建置之間變更，拒絕混用不同 SDK 的 Roslyn 元件"]
        manifest = scratch / "manifest.json"
        manifest.write_text(json.dumps(pending, ensure_ascii=False), encoding="utf-8")
        work = cache if use_cache else scratch
        _private_mkdir(work)
        proj_file = work / "roslyn-indexer.csproj"
        program_file = work / "Program.cs"
        dll = work / "bin" / "Release" / probe["target_framework"] / "roslyn-indexer.dll"
        digest_file = work / ".compiled-sha256"
        if use_cache and any(item.is_symlink() for item in
                             (work, work / "bin", work / "bin/Release",
                              work / "bin/Release" / probe["target_framework"],
                              proj_file, program_file, dll, digest_file)):
            return {}, ["Roslyn 快取內容含 symbolic link，拒絕執行；可將快取設為 0 後重試"]
        expected = None
        if dll.is_file() and digest_file.is_file() and not dll.is_symlink():
            expected = hashlib.sha256(dll.read_bytes()).hexdigest()
        valid = (expected is not None and digest_file.read_text(encoding="utf-8") == expected
                 and proj_file.is_file() and program_file.is_file()
                 and not proj_file.is_symlink() and not program_file.is_symlink()
                 and proj_file.read_text(encoding="utf-8") == project
                 and program_file.read_bytes() == program)
        if not valid:
            proj_file.write_text(project, encoding="utf-8")
            program_file.write_bytes(program)
            try:
                build = subprocess.run(
                    [probe["executable"], "build", str(proj_file), "--configuration", "Release",
                     "--nologo", f"-p:RoslynIndexerTargetFramework={probe['target_framework']}"],
                    capture_output=True, text=True, encoding="utf-8",
                    errors="replace", cwd=scratch, env=env, timeout=180, check=False)
            except (OSError, subprocess.TimeoutExpired) as exc:
                return {}, [f"Roslyn 編譯失敗：{type(exc).__name__}"]
            if build.returncode != 0 or not dll.is_file() or dll.is_symlink():
                output = (build.stdout + "\n" + build.stderr)
                if "CS1705" in output:
                    return {}, ["Roslyn CS1705：SDK Roslyn 與 indexer TargetFramework 不相容"
                                f"（SDK {probe.get('sdk_version')}, TFM {probe['target_framework']}）；"
                                "請確認 dotnet SDK 安裝及全域 SDK 版本設定"]
                if use_cache and any(code in output.lower() for code in (
                        "access denied", "permission denied", "access to the path",
                        "unauthorizedaccessexception", "msb3026", "msb3027")):
                    parsed, issues = _run_roslyn(root, pending, probe, no_cache=True)
                    return parsed, ["Roslyn 快取權限不足，已使用隔離暫存編譯", *issues]
                return {}, ["Roslyn indexer 編譯失敗（非受測專案編譯）；請核對 SDK 及工具相依"]
            digest_file.write_text(hashlib.sha256(dll.read_bytes()).hexdigest(),
                                   encoding="utf-8")
        try:
            result = subprocess.run(
                [probe["executable"], str(dll), str(root), str(manifest)],
                capture_output=True, text=True, encoding="utf-8",
                errors="replace", cwd=scratch, env=env, timeout=180, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {}, [f"Roslyn 執行失敗：{type(exc).__name__}"]
        line = next((x.removeprefix("SCROSLYN_JSON:") for x in result.stdout.splitlines()
                     if x.startswith("SCROSLYN_JSON:")), None)
        if result.returncode != 0 or not line:
            return {}, ["Roslyn 無法輸出有效索引（SDK 或相依套件可能未就緒）"]
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            return {}, ["Roslyn 索引 JSON 無法解析"]
        data = {r["path"]: r for r in payload.get("files", [])
                if isinstance(r, dict) and "path" in r}
        return data, payload.get("errors", [])


def cross_file_call_hints(indexed: dict[str, dict]) -> dict[str, list[dict]]:
    """P1：語意符號優先、歧義不丟棄；僅產生候選，不自動完成安全查核。

    獨立編譯的專案引用、執行時多型與 dynamic 皆可能影響真實目標。
    一個呼叫點的全部候選會保留；不得以[:8]、[:200] 靜默截斷。
    """
    from collections import defaultdict
    import hashlib

    declarations: dict[str, list[tuple[str, dict]]] = defaultdict(list)
    for path, entry in indexed.items():
        for method in entry.get("methods", []):
            if isinstance(method, dict) and isinstance(method.get("name"), str):
                declarations[method["name"]].append((path, method))
    graph: dict[str, list[dict]] = {}
    for path, entry in indexed.items():
        hints: list[dict] = []
        for call_number, call in enumerate(entry.get("calls", [])):
            name = call.get("called_method")
            line = call.get("line") or call.get("caller_line")
            if not isinstance(name, str) or not isinstance(line, int) or line < 1:
                continue
            caller = str(call.get("containing_method") or "")
            count = call.get("argument_count")
            callsite_id = hashlib.sha256(
                f"{path}|{line}|{caller}|{name}|{count}|{call_number}".encode("utf-8")
            ).hexdigest()[:24]
            semantic = call.get("semantic_targets")
            precise = []
            if isinstance(semantic, list):
                precise = [
                    target for target in semantic
                    if isinstance(target, dict) and target.get("path") in indexed
                    and target["path"] != path
                ]
            if precise:
                targets = sorted(precise, key=lambda x: (x["path"], x.get("line") or 0))
                resolution = ("semantic_dispatch_candidate"
                              if call.get("semantic_state") == "dispatch_candidate"
                              else "semantic_symbol_candidate")
                reason = "Roslyn 合成編譯推測符號；須核對實際專案綁定與 DI"
            elif call.get("semantic_state") == "symbol_candidate" and semantic:
                # Roslyn 已找到同檔直接呼叫；不得再用常見方法名向其他檔案
                # 虛構跨檔邊。動態分派不走此分支。
                continue
            elif call.get("semantic_state") == "dispatch_candidate":
                # 僅發現介面/虛擬宣告而無跨檔實作，不表示執行時不存在外部實作。
                # 保留未解呼叫點，交由 Agent 核對 DI/Proxy/其它專案。
                targets = []
                resolution = "dispatch_requires_manual_search"
                reason = "多型呼叫缺少可定位跨檔實作；須追查 DI、覆寫與執行期配置"
            else:
                candidates = [
                    (target, method) for target, method in declarations.get(name, [])
                    if target != path and (
                        not isinstance(count, int)
                        or not isinstance(method.get("parameter_count"), int)
                        or method["parameter_count"] == count
                    )
                ]
                # 由 Roslyn 得到的 receiver_type 可限縮候選，不把 receiver 變數名稱
                # 當成真實型別，也不把沒有比對到的目標誤認為安全。
                receiver_type = call.get("receiver_type")
                typed = [
                    (target, method) for target, method in candidates
                    if isinstance(receiver_type, str)
                    and receiver_type.rsplit(".", 1)[-1].split("<", 1)[0]
                    == method.get("containing_type")
                ]
                matches = typed or candidates
                targets = [
                    {"path": target, "method": method["name"], "line": method.get("line"),
                     "containing_type": method.get("containing_type")}
                    for target, method in matches
                ]
                resolution = ("receiver_type_candidate" if typed else "name_only_ambiguous")
                reason = ("Roslyn 未能確認直接跨檔符號；同名方法或介面分派可能有歧義"
                          if matches else "呼叫未取得儲存庫內可用目標")
            if not targets and resolution != "dispatch_requires_manual_search":
                # 外部框架呼叫無本地目標時不產生大量虛構的跨檔邊。
                # 介面或動態分派仍以上方保留的未解呼叫點追查。
                continue
            unique = {(t["path"], t.get("line") or 0, t.get("method") or name): t
                      for t in targets}
            targets = [unique[k] for k in sorted(unique)]
            hints.append({
                "id": callsite_id,
                "caller_method": caller,
                "caller_line": line,
                "called_method": name,
                "receiver": call.get("receiver"),
                "receiver_type": call.get("receiver_type"),
                "resolution": resolution,
                "reason": reason,
                "candidate_count": len(targets),
                "possible_targets": targets,
                "requires_manual_verification": True,
            })
        if hints:
            graph[path] = sorted(hints, key=lambda x: (x["caller_line"], x["id"]))
    return graph


def prepare(root: Path, mode: str = "full") -> dict:
    root = root.resolve()
    if not root.is_dir() or root == SKILL_ROOT or SKILL_ROOT in root.parents:
        raise ValueError("受測專案路徑不存在或指向 Skill 本身")
    adapter = ADAPTERS[0]  # 第一階段僅啟用現代 .NET；往後可由 registry 選擇。
    detection = adapter.detect(root)
    report_dir = root / REPORT_ROOT
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
    # 語意符號解析依賴完整工作區：任何來源／組態變更都可能改變
    # 未變更呼叫端的目標，因此不可重用舊的 semantic_targets。
    # 只有完整來源 SHA256 一致時，才重用既有 Roslyn 候選索引。
    semantic_invalidated = bool(changed or removed)
    reused = ({p: old_entries[p] for p in csharp if p in old_entries}
              if not semantic_invalidated else {})
    pending = [p for p in csharp if p not in reused]
    parsed, errors = _run_roslyn(root, pending, roslyn)
    indexed = {**reused, **parsed}
    # 完整來源 SHA256、分析器契約與 SDK 版本全部相符時，跨檔索引可原樣重用。
    # 任何來源增刪改或版本差異都回到保守重算，不沿用安全判定。
    relationships_reused = (mode == "incremental" and compatible
                            and not changed and not removed
                            and indexed == previous.get("roslyn_files")
                            and isinstance(previous.get("cross_file_call_hints"), dict)
                            and isinstance(previous.get("typed_relationships"), list))
    if relationships_reused:
        call_hints = previous["cross_file_call_hints"]
        typed_relationships = previous["typed_relationships"]
    else:
        call_hints = cross_file_call_hints(indexed)
        typed_relationships = build_relationships(root, sorted(source), call_hints)
    # 變更的呼叫端/組態可能影響未變動來源；沒有受驗證依賴閉包前採保守重審。
    recheck = sorted(source) if changed or removed or not compatible or mode == "full" else []
    payload = {
        "schema_version": INDEX_VERSION, "control_effectiveness_version": 1, "control_outcome_version": 1, "decision_adjudication_version": 1, "decision_quality_version": 1, "cross_file_evidence_version": 1, "adversarial_second_pass_version": 1, "adversarial_quality_version": 1, "evidence_integrity_version": 1,
        "adapter": adapter.name, "mode": mode,
        "roslyn_version": ROSLYN_VERSION, "sdk_version": roslyn.get("sdk_version"),
        "candidate_version": CANDIDATE_VERSION, "rule_candidates": rule_candidates,
        "source_hashes": source, "roslyn_files": indexed,
        "cross_file_call_hints": call_hints,
        "callsite_candidate_count": sum(len(v) for v in call_hints.values()),
        "typed_relationships": typed_relationships,
        "changed_paths": changed, "removed_paths": removed, "recheck_paths": recheck,
        "codegraph": codegraph, "roslyn": {k: v for k, v in roslyn.items() if k != "executable"},
        "roslyn_errors": errors,
        "warning": "結構索引及快取不能代替安全審查證據；不得直接寫入 completed/pass/na 或繼承失效的 Finding。"
    }
    # 工作樹快照固定單次審查所使用的完整來源版本，禁止混用舊證據。
    initialize_snapshot(root, source, excluded)
    write_json_atomic(index, payload)
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
        "typed_relationship_count": len(typed_relationships),
        "relationships_reused": relationships_reused,
        "typed_relationship_kinds": sorted({edge["kind"] for edge in typed_relationships}),
        "cross_file_caller_count": len(call_hints),
        "cross_file_callsite_count": sum(len(v) for v in call_hints.values()),
        "callsite_candidate_target_count": sum(
            len(x["possible_targets"]) for calls in call_hints.values() for x in calls),
        "cross_file_examples": [
            {"path": path, "calls": calls[:3]} for path, calls in list(call_hints.items())[:5]
        ],
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
    from review_log import logged_main
    raise SystemExit(logged_main(main, "structure_index"))
