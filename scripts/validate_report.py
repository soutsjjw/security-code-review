#!/usr/bin/env python3
"""驗證 70 項檢核、報告 Schema、跨資料引用、來源行號與 HTML 一致性。"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from report_common import ROOT, extract_html_report, load_json, validate_data, validate_html
from source_reader import DEFAULT_LEGACY_ENCODINGS


def main() -> int:
    p = argparse.ArgumentParser(description='驗證資安報告 JSON 與 HTML')
    p.add_argument('--report', type=Path, help='完整 report.json（若只有 HTML，可直接提供 --html）')
    p.add_argument('--html', type=Path, help='已產生的 HTML 報告')
    p.add_argument('--rules', type=Path, default=ROOT/'rules.json')
    p.add_argument('--schema-dir', type=Path, default=ROOT/'schemas')
    p.add_argument('--template', type=Path, default=ROOT/'templates/security-report.html')
    p.add_argument('--source-root', type=Path)
    p.add_argument('--strict-sources', action='store_true')
    p.add_argument('--source-encodings', default=','.join(DEFAULT_LEGACY_ENCODINGS))
    p.add_argument('--allow-demo', action='store_true')
    args = p.parse_args()
    if args.report is None and args.html is None:
        p.error('請提供 --report 或 --html')
    if not args.allow_demo and (args.source_root is None or not args.strict_sources):
        p.error('正式報告驗證必須提供 --source-root 與 --strict-sources')
    try:
        if args.strict_sources and args.source_root is None:
            raise ValueError('--strict-sources 需要搭配 --source-root')
        html = args.html.read_text(encoding='utf-8') if args.html else None
        if args.report:
            data = load_json(args.report)
        else:
            data, _ = extract_html_report(html)
        ignored_artifacts = (args.report, args.html)
        result = validate_data(data, rules_path=args.rules, schema_dir=args.schema_dir,
                               source_root=args.source_root, strict_sources=args.strict_sources,
                               allow_demo=args.allow_demo,
                               source_encodings=tuple(x.strip() for x in args.source_encodings.split(',') if x.strip()),
                               ignored_artifacts=ignored_artifacts)
        if html is not None:
            template = args.template.read_text(encoding='utf-8')
            checked = validate_html(html, data, template)
            result.errors.extend(checked.errors)
            result.warnings.extend(checked.warnings)
        result.print()
        print(f'CHECKS: {len(data.get("assessment", {}).get("checks", []))}；FINDINGS: {len(data.get("assessment", {}).get("findings", []))}')
        return 0 if result.ok else 1
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        print('ERROR:', exc, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
