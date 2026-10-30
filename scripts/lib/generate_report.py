#!/usr/bin/env python3
"""從 report.json 或 assessment.json 產生固定版型、可離線開啟的資安 HTML 報告。"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from report_common import ROOT, load_json, render_html, validate_data, validate_html
from source_reader import DEFAULT_LEGACY_ENCODINGS
from scope_inventory import build_scope_inventory
from security_level import infer_security_level
from report_enrichment import (
    resolve_personal_data, detect_reviewer, build_overall_risk, build_pending_information,
)
from standard_guides import load_owasp_2025_categories
from system_baseline import build_system_baseline, review_from_report
from web_guide import build_web_guide_index
from web_appendix1 import build_appendix1, review_from_report as appendix_review_from_report
from web_headers import build_appendix3, review_from_report as header_review_from_report
from review_core import write_json_atomic


def parse_args():
    p = argparse.ArgumentParser(description='依 70 項資安審查 JSON 產出獨立 HTML 報告')
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument('--report', type=Path, help='完整 report.json（含 project/assessment/rules/presentation）')
    src.add_argument('--assessment', type=Path, help='既有 assessment.json，需搭配 --project')
    p.add_argument('--project', type=Path, help='系統顯示資訊 JSON，內容為 project 物件')
    p.add_argument('--presentation', type=Path, help='選填報告呈現欄位 JSON，內容為 presentation 物件')
    p.add_argument('--web-appendix3-assessment', type=Path, help='附件3六項 HTTP 標頭獨立查證，預設 assessment.json 同目錄 web_appendix3_assessment.json')
    p.add_argument('--web-appendix1-assessment', type=Path, help='選填附件1獨立查檢結果，預設 assessment.json 同目錄 web_appendix1_assessment.json')
    p.add_argument('--baseline-assessment', type=Path, help='選填獨立 80 項驗證資料（預設自動讀取 assessment.json 同目錄 baseline_assessment.json）')
    p.add_argument('--rules', type=Path, default=ROOT/'rules.json', help='70 項規則主檔')
    p.add_argument('--schema-dir', type=Path, default=ROOT/'schemas')
    p.add_argument('--template', type=Path, default=ROOT/'templates/security-report.html')
    p.add_argument('--source-root', type=Path, help='被審查程式碼的實際根目錄，用於路徑與行號檢查')
    p.add_argument('--strict-sources', action='store_true', help='來源檔缺失或行號不合法時禁止產生報告')
    p.add_argument('--source-encodings', default=','.join(DEFAULT_LEGACY_ENCODINGS), help='UTF-8 無法解碼時的舊編碼，例如 cp950,cp1252')
    p.add_argument('--allow-demo', action='store_true', help='僅供測試：允許 presentation.demo=true')
    p.add_argument('--save-report', type=Path, help='同步保存標準化 report.json；須與 --output 不同')
    p.add_argument('--output', '-o', required=True, type=Path, help='輸出完整 HTML 路徑')
    return p.parse_args()


def main() -> int:
    a = parse_args()
    try:
        if a.strict_sources and a.source_root is None:
            raise ValueError('--strict-sources 需要搭配 --source-root')
        if not a.allow_demo and (a.source_root is None or not a.strict_sources):
            raise ValueError('正式報告必須提供 --source-root 及 --strict-sources 以驗證完整逐檔審查')
        if a.report:
            if a.project or a.presentation:
                raise ValueError('使用 --report 時不得同時指定 --project 或 --presentation')
            data = load_json(a.report)
        else:
            if a.project is None:
                raise ValueError('--assessment 模式必須提供 --project')
            rule_file = load_json(a.rules)
            base_rules = rule_file['rules'] if isinstance(rule_file, dict) else rule_file
            data = {
                'report_schema_version': '2.1.0',
                'project': load_json(a.project),
                'assessment': load_json(a.assessment),
                'rules': [
                    {'id': r['id'], 'title': r['title'], 'category': r['category'],
                     'origin': {'legacy_levels': r.get('origin', {}).get('legacy_levels', '依 Profile')}}
                    for r in base_rules
                ],
                'presentation': load_json(a.presentation) if a.presentation else {},
            }
        # 第二層 80 項基準不能從程式碼規則 Pass 推定通過。
        if a.report:
            if a.baseline_assessment:
                raise ValueError('--report 模式不得指定 --baseline-assessment')
            review = review_from_report(data.get('system_baseline', {}))
            baseline_source = None
        else:
            baseline_source = (a.baseline_assessment if a.baseline_assessment else
                               a.assessment.parent / 'baseline_assessment.json')
            review = load_json(baseline_source) if baseline_source.is_file() else None
        data['system_baseline'] = build_system_baseline(data['project'], review)

        # 官方 2025 風險類別與既有規則僅為「相關」對照，並非十項合規結果。
        # --report 模式也重新按版本化清單產生分類，不相信舊報告中過時的關聯。
        mapping_rules = load_json(a.rules)
        source_rules = mapping_rules['rules'] if isinstance(mapping_rules, dict) else mapping_rules
        if a.report:
            if a.web_appendix1_assessment:
                raise ValueError('--report 模式不可搭配 --web-appendix1-assessment')
            appendix_input = None
            appendix_review = appendix_review_from_report(data.get('web_guide_v32_appendix1', {}))
        else:
            appendix_input = (a.web_appendix1_assessment if a.web_appendix1_assessment else
                              a.assessment.parent / 'web_appendix1_assessment.json')
            appendix_review = load_json(appendix_input) if appendix_input.is_file() else None
        data['web_guide_v32_appendix1'] = build_appendix1(data['project'], source_rules, appendix_review)
        # HTTP 標頭六項屬 CR-05 技術子項，不新增六條主規則，也不自動 Pass。
        if a.report:
            if a.web_appendix3_assessment:
                raise ValueError('--report 模式不可搭配 --web-appendix3-assessment')
            header_input = None
            header_review = header_review_from_report(data.get('web_guide_v32_appendix3', {}))
        else:
            header_input = (a.web_appendix3_assessment if a.web_appendix3_assessment else
                            a.assessment.parent / 'web_appendix3_assessment.json')
            header_review = load_json(header_input) if header_input.is_file() else None
        data['web_guide_v32_appendix3'] = build_appendix3(source_rules, header_review)
        mapped_owasp = load_owasp_2025_categories(source_rules)
        if not a.report:
            data['current_ruleset_version'] = mapping_rules['ruleset_version']
        data['web_guide_v32'] = build_web_guide_index(source_rules)
        for report_rule in data['rules']:
            report_rule['owasp_2025_categories'] = [
                {"id": item["id"], "title": item["title"], "coverage_gap": item["coverage_gap"]}
                for item in mapped_owasp.get(report_rule["id"], [])
            ]
        standards = data['presentation'].setdefault('standards', [])
        if isinstance(standards, list):
            label = 'OWASP Top 10:2025（風險分類，非合規判定）'
            if label not in standards:
                standards.append(label)
            tw_label = '資通系統防護基準驗證實務 V1.3（普／中／高獨立驗證）'
            if tw_label not in standards:
                standards.append(tw_label)
            guide_label = 'WEB應用程式安全參考指引 V3.2（ASP.NET/.NET 與通用 Web 控制）'
            if guide_label not in standards:
                standards.append(guide_label)
            appendix_label = 'WEB應用程式安全參考指引 V3.2 附件1（55項獨立查檢）'
            if appendix_label not in standards:
                standards.append(appendix_label)
            header_label = 'WEB應用程式安全參考指引 V3.2 附件3（六項 HTTP 安全標頭）'
            if header_label not in standards:
                standards.append(header_label)
        # 若尚未提供正式分級，根據已完成的逐檔審查自動產生初判或待確認說明。
        project = data['project']
        if project.get('security_level') not in ('A', 'B', 'C', 'D', 'E', '不適用'):
            if 'security_level_assessment' not in project:
                encodings = tuple(x.strip() for x in a.source_encodings.split(',') if x.strip())
                project['security_level_assessment'] = infer_security_level(
                    data['assessment'], a.source_root, encodings
                )
        # 使用真實審查紀錄生成一致的 HTML／JSON 摘要，不改寫原始 assessment／project。
        if not a.report:
            encodings = tuple(x.strip() for x in a.source_encodings.split(',') if x.strip())
            resolve_personal_data(project, data['assessment'], a.source_root, encodings)
            presentation = data['presentation']
            presentation['reviewer'] = detect_reviewer(presentation.get('reviewer'))
            # init 預設的內部名稱不是實際執行介面；僅在報告資料中統一，不改寫原始 assessment.json。
            for check in data['assessment'].get('checks', []):
                if check.get('reviewer') == 'security-code-review-agent':
                    check['reviewer'] = presentation['reviewer']
            presentation['overall_risk'] = build_overall_risk(data['assessment'])
            presentation['pending_information'] = build_pending_information(
                project, data['assessment'], presentation.get('limitations', []),
                presentation.get('review_ratio_explanation')
            )
        ignored_artifacts = (a.report, a.save_report, a.output)
        if a.source_root is not None:
            data['scope_inventory'] = build_scope_inventory(
                data['assessment'], a.source_root, ignored_artifacts=ignored_artifacts)
        result = validate_data(data, rules_path=a.rules, schema_dir=a.schema_dir,
                               source_root=a.source_root, strict_sources=a.strict_sources,
                               allow_demo=a.allow_demo,
                               source_encodings=tuple(x.strip() for x in a.source_encodings.split(',') if x.strip()),
                               ignored_artifacts=ignored_artifacts)
        result.print()
        if not result.ok:
            return 1
        template = a.template.read_text(encoding='utf-8')
        html = render_html(template, data)
        html_result = validate_html(html, data, template)
        html_result.print()
        if not html_result.ok:
            return 1
        protected_inputs = [a.report, a.assessment, a.project, a.presentation, baseline_source, appendix_input, header_input,
                            a.rules, a.template, a.schema_dir / 'report.schema.json',
                            a.schema_dir / 'assessment.schema.json']
        inputs = {p.resolve() for p in protected_inputs if p is not None}
        destinations = [a.output] + ([a.save_report] if a.save_report else [])
        if len({p.resolve() for p in destinations}) != len(destinations):
            raise ValueError('--save-report 與 --output 不得指向相同檔案')
        if any(p.resolve() in inputs for p in destinations):
            raise ValueError('輸出路徑不得覆寫輸入資料、規則、Schema 或模板')
        if a.save_report:
            a.save_report.parent.mkdir(parents=True, exist_ok=True)
            write_json_atomic(a.save_report, data)
            print('SAVED:', a.save_report)
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(html, encoding='utf-8')
        print(f'GENERATED: {a.output}（{len(data["assessment"]["checks"])} 項、{len(data["assessment"]["findings"])} 個發現）')
        return 0
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print('ERROR:', exc, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
