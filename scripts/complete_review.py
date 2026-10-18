#!/usr/bin/env python3
"""從受測專案目錄完成結構驗證、HTML 生成及最終驗證。

注意：本程式不進行 AI 原始碼分析。分析與寫入 assessment.json 由 Skill Agent 負責。
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description='完成受測專案的資安報告；輸出到該專案的 reports/security-code-review/')
    p.add_argument('--target', type=Path, default=Path.cwd(), help='受測專案根目錄（預設：目前工作目錄）')
    p.add_argument('--output-dir', default='reports/security-code-review', help='受測專案內報告目錄，相對路徑')
    return p.parse_args()


def within(base: Path, child: Path) -> bool:
    return child.is_relative_to(base)


def main() -> int:
    args = parse_args()
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
    html = out / f'CodeReview_{date.replace("-", "")}.html'
    report = out / 'report.json'
    steps = [
        [sys.executable, str(SKILL_ROOT / 'scripts/validate_assessment.py'), str(assessment)],
        [sys.executable, str(SKILL_ROOT / 'scripts/generate_report.py'),
         '--assessment', str(assessment), '--project', str(project),
         '--source-root', str(target), '--strict-sources',
         '--save-report', str(report), '--output', str(html)],
        [sys.executable, str(SKILL_ROOT / 'scripts/validate_report.py'),
         '--report', str(report), '--html', str(html),
         '--source-root', str(target), '--strict-sources'],
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
    sys.exit(main())
