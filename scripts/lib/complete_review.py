#!/usr/bin/env python3
"""從受測專案目錄完成結構驗證、HTML 生成及最終驗證。

注意：本程式不進行 AI 原始碼分析。分析與寫入 assessment.json 由 Skill Agent 負責。
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_ROOT / 'scripts'))
from source_coverage import build_source_coverage
from assessment_consistency import project_placeholder_errors


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description='完成受測專案的資安報告；輸出到該專案的 reports/security-code-review/')
    p.add_argument('--target', type=Path, default=Path.cwd(), help='受測專案根目錄（預設：目前工作目錄）')
    p.add_argument('--output-dir', default='reports/security-code-review', help='受測專案內報告目錄，相對路徑')
    p.add_argument('--source-encodings', default='cp950,cp1252', help='舊式來源編碼回退順序')
    p.add_argument('--categories', action='append', metavar='AC,AU', help='產生各分類獨立 HTML/JSON，僅部分審查')
    return p.parse_args()


def within(base: Path, child: Path) -> bool:
    return child.is_relative_to(base)


def main() -> int:
    args = parse_args()
    if args.categories:
        if len(args.categories) != 1:
            print('ERROR: --categories 僅能指定一次', file=sys.stderr)
            return 2
        if args.output_dir != 'reports/security-code-review':
            print('ERROR: 分類報告固定儲存於 partial/<分類>，不得自訂 --output-dir', file=sys.stderr)
            return 2
        from partial_report import main as complete_partial
        return complete_partial(['--target', str(args.target), '--categories', args.categories[0]])
    target = args.target.resolve()
    if not target.is_dir():
        print(f'ERROR: 受測目錄不存在：{target}', file=sys.stderr)
        return 2
    if target == SKILL_ROOT or within(SKILL_ROOT, target):
        print('ERROR: 受測目錄不可指向 Skill 安裝位置', file=sys.stderr)
        return 2
    if Path(args.output_dir).is_absolute() or '..' in Path(args.output_dir).parts:
        print('ERROR: --output-dir 必須是受測專案內的相對路徑', file=sys.stderr)
        return 2
    out = (target / args.output_dir).resolve()
    if not within(target, out) or within(SKILL_ROOT, out):
        print('ERROR: 輸出目錄必須位於受測專案內', file=sys.stderr)
        return 2
    if os.environ.get("SECURITY_CODE_REVIEW_EXECUTION_MODE") == "optimized":
        try:
            from review_log import _load, _paths
            from execution_boundary_events import verify_run
            state = _load(_paths(target)[1])
            if not state or not state.get("run_id"):
                raise ValueError("缺少有效執行紀錄")
            boundary = verify_run(target, state["run_id"])
            if boundary["blocked_batches"]:
                raise ValueError("仍有待覆核／已維持的 block 級違規：" +
                                 ", ".join(boundary["blocked_batches"][:12]))
        except (ValueError, OSError, KeyError) as exc:
            print(f"ERROR: P0 執行邊界未通過，禁止正式報告交付：{exc}", file=sys.stderr)
            return 2
    assessment = out / 'assessment.json'
    project = out / 'project.json'
    presentation = out / 'presentation.json'
    for f in (assessment, project):
        if not f.is_file():
            print(f'ERROR: 缺少 {f}；必須先由 Agent 完成原始碼審查與 JSON 寫入', file=sys.stderr)
            return 2
    try:
        obj = json.loads(assessment.read_text(encoding='utf-8'))
        date = obj['assessment_date']
        from datetime import date as dt_date
        dt_date.fromisoformat(date)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f'ERROR: assessment.json 審查日期無效：{exc}', file=sys.stderr)
        return 2
    try:
        project_data = json.loads(project.read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        print(f'ERROR: project.json 無法讀取：{exc}', file=sys.stderr)
        return 2
    placeholder_errors = project_placeholder_errors(project_data)
    if placeholder_errors:
        for problem in placeholder_errors:
            print('ERROR: ' + problem, file=sys.stderr)
        return 1
    # 在執行報告產生前拒絕未涵蓋全部應審查來源的假性 70/70。
    try:
        coverage = build_source_coverage(obj, target)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f'ERROR: 來源檔案盤點失敗：{exc}', file=sys.stderr)
        return 2
    if coverage['review_integrity_errors']:
        print(f"ERROR: 逐檔規則審查佐證驗證失敗（{len(coverage['review_integrity_errors'])} 項）：", file=sys.stderr)
        for problem in coverage['review_integrity_errors'][:20]:
            print('  ' + problem, file=sys.stderr)
        if any("sha256" in problem.lower() for problem in coverage["review_integrity_errors"]):
            print("ERROR: 請先唯讀執行 hash_audit.py --target <TARGET_ROOT> "
                  "列出所有失配檔案，核對版本後再重審；不可直接批次重算 SHA256。", file=sys.stderr)
        print('ERROR: 未修改原始審查資料、Finding 或既有報告。', file=sys.stderr)
        return 1
    if coverage['missing_source_file_count']:
        print(f"ERROR: 原始碼審查覆蓋不足："
              f"{coverage['reviewed_source_file_count']}/{coverage['source_file_count']}，"
              f"尚有 {coverage['missing_source_file_count']} 個檔案未審查；"
              f"依類型 {coverage['missing_by_type']}", file=sys.stderr)
        for missing in coverage['missing_source_paths'][:20]:
            print(f'  未審查：{missing}', file=sys.stderr)
        print('ERROR: 請先完成逐檔審查並記入 completed 規則的 inspected_paths；'
              '現有 assessment.json、Finding 及報告均保持不變。', file=sys.stderr)
        return 1
    html = out / f'CodeReview_{date.replace("-", "")}.html'
    report = out / 'report.json'
    steps = [
        [sys.executable, str(SKILL_ROOT / 'scripts/validate_assessment.py'), str(assessment), '--source-root', str(target)],
        [sys.executable, str(SKILL_ROOT / 'scripts/generate_report.py'),
         '--assessment', str(assessment), '--project', str(project),
         '--source-root', str(target), '--strict-sources', '--source-encodings', args.source_encodings,
         '--save-report', str(report), '--output', str(html)],
        [sys.executable, str(SKILL_ROOT / 'scripts/validate_report.py'),
         '--report', str(report), '--html', str(html),
         '--source-root', str(target), '--strict-sources', '--source-encodings', args.source_encodings],
    ]
    if presentation.is_file():
        steps[1].extend(['--presentation', str(presentation)])
    for idx, command in enumerate(steps, 1):
        print(f'\nSTEP {idx}/{len(steps)}：{["檢核 JSON", "產生 HTML", "驗證 HTML"][idx-1]}', flush=True)
        result = subprocess.run(command, cwd=target, check=False)
        if result.returncode != 0:
            print(f'ERROR: 第 {idx} 步失敗，未通過完整報告驗證（exit {result.returncode}）', file=sys.stderr)
            return result.returncode
    print(f'\nPASS: {html}')
    print(f'PASS: {report}')
    return 0


if __name__ == '__main__':
    from review_log import logged_main
    sys.exit(logged_main(main, "report"))
