#!/usr/bin/env python3
"""資安審查報告共同驗證／渲染程式（只使用本地檔案）。"""
from __future__ import annotations

import json
import re
import textwrap
from collections import Counter
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from system_baseline import validate_system_baseline
from web_guide import validate_web_guide_index
from web_appendix1 import validate_appendix1
from web_headers import validate_appendix3
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from source_reader import DEFAULT_LEGACY_ENCODINGS, read_source_text
from review_completion import completion_errors
from review_decision import decision_quality_errors
from scope_inventory import build_scope_inventory
from source_coverage import build_source_coverage

ROOT = Path(__file__).resolve().parents[1]
SLOT_RE = re.compile(r'(<script\s+id="report-data"\s+type="application/json">)(.*?)(</script>)', re.DOTALL)
RULE_COUNTS = {'AC': 8, 'AU': 10, 'IN': 8, 'CR': 6, 'EH': 6, 'LG': 10, 'DP': 4, 'PD': 8, 'BC': 7, 'SI': 3}
SAFE_ID_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_-]*$')


@dataclass
class Result:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def print(self) -> None:
        for issue in self.errors:
            print('ERROR:', issue)
        for issue in self.warnings:
            print('WARN:', issue)
        if self.ok:
            print('PASS: 報告 Schema、關聯資料與模板驗證通過')
        else:
            print(f'FAIL: {len(self.errors)} 個錯誤、{len(self.warnings)} 個提醒')


def load_json(path: Path) -> Any:
    with path.open('r', encoding='utf-8') as f:
        return json.load(f)


def canonical_rules(path: Path) -> dict[str, dict[str, Any]]:
    data = load_json(path)
    rules = data['rules'] if isinstance(data, dict) else data
    if not isinstance(rules, list):
        raise ValueError('rules.json 必須包含 rules 陣列')
    indexed = {r['id']: r for r in rules}
    if len(indexed) != 70 or len(rules) != 70:
        raise ValueError('rules.json 必須有 70 個不重複的規則')
    if dict(Counter(r.get('category') for r in rules)) != RULE_COUNTS:
        raise ValueError('rules.json 分類數量不正確')
    return indexed


def get_schema_validator(schema_dir: Path) -> Draft202012Validator:
    report_schema = load_json(schema_dir / 'report.schema.json')
    assessment_schema = load_json(schema_dir / 'assessment.schema.json')
    Draft202012Validator.check_schema(report_schema)
    Draft202012Validator.check_schema(assessment_schema)
    registry = Registry().with_resource(
        'assessment.schema.json', Resource.from_contents(assessment_schema)
    )
    return Draft202012Validator(report_schema, registry=registry, format_checker=FormatChecker())


def _verify_line(item: dict[str, Any], label: str, source_root: Path | None, result: Result, strict_sources: bool, source_encodings: tuple[str, ...]):
    src_path = item.get('path')
    if not src_path:
        return
    src_path = str(src_path).replace('\\', '/')
    if src_path.startswith('/') or src_path.startswith('//') or re.match(r'^[A-Za-z]:', src_path):
        result.errors.append(f'{label}: 不允許絕對來源路徑 {src_path!r}')
        return
    raw_parts = src_path.split('/')
    if '..' in raw_parts or not src_path.strip() or '\x00' in src_path:
        result.errors.append(f'{label}: 無效或跨出專案的來源路徑 {src_path!r}')
        return
    start, end = item.get('line_start'), item.get('line_end')
    if start is not None and end is not None and start > end:
        result.errors.append(f'{label}: line_start 大於 line_end')
    if source_root is None:
        if strict_sources:
            result.errors.append(f'{label}: --strict-sources 需要 --source-root 才能驗證實際來源檔')
        return
    source_root = source_root.resolve()
    resolved = (source_root / src_path).resolve()
    if not resolved.is_relative_to(source_root):
        result.errors.append(f'{label}: 路徑跨出 --source-root {src_path!r}')
        return
    if not resolved.is_file():
        (result.errors if strict_sources else result.warnings).append(f'{label}: 無法找到來源檔 {src_path!r}')
        return
    if start is None or end is None:
        (result.errors if strict_sources else result.warnings).append(f'{label}: 缺少來源行號')
        return
    try:
        text, encoding = read_source_text(resolved, source_encodings)
        num_lines = len(text.splitlines())
        if encoding in source_encodings:
            warning = f'{src_path}: 使用舊編碼 {encoding} 解碼來源檔，請核對編碼'
            if warning not in result.warnings:
                result.warnings.append(warning)
    except (OSError, UnicodeError) as exc:
        (result.errors if strict_sources else result.warnings).append(f'{label}: 來源檔無法讀取：{exc}')
        return
    if end > num_lines:
        (result.errors if strict_sources else result.warnings).append(f'{label}: 行號 {start}-{end} 超過檔案總行數 {num_lines}')


def validate_data(
    data: dict[str, Any], *, rules_path: Path | None = None,
    schema_dir: Path | None = None, source_root: Path | None = None,
    strict_sources: bool = False, allow_demo: bool = False,
    source_encodings: tuple[str, ...] = DEFAULT_LEGACY_ENCODINGS,
    ignored_artifacts: tuple[Path | None, ...] = (),
) -> Result:
    result = Result()
    rules_path = rules_path or ROOT / 'rules.json'
    schema_dir = schema_dir or ROOT / 'schemas'
    try:
        validator = get_schema_validator(schema_dir)
        schema_errors = sorted(validator.iter_errors(data), key=lambda e: (list(map(str, e.absolute_path)), e.message))
        for error in schema_errors[:100]:
            location = '$' + ''.join(f'[{i!r}]' for i in error.absolute_path)
            result.errors.append(f'Schema {location}: {error.message}')
        if len(schema_errors) > 100:
            result.errors.append(f'Schema 其餘 {len(schema_errors) - 100} 個錯誤未顯示')
    except (ValueError, OSError, KeyError) as exc:
        result.errors.append(f'Schema 無法載入：{exc}')
        return result
    if result.errors:
        return result

    try:
        master = canonical_rules(rules_path)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        result.errors.append(f'規則主檔無法驗證：{exc}')
        return result
    assessment = data['assessment']
    # 70/70 是規則執行進度，不代表受測程式已全數審查。正式驗證須核對檔案覆蓋。
    if not allow_demo and (source_root is None or not strict_sources):
        result.errors.append('正式報告必須提供 --source-root 與 --strict-sources 以核對全部 file_reviews')
    if strict_sources and source_root is not None and not allow_demo:
        try:
            coverage = build_source_coverage(assessment, source_root, ignored_artifacts=ignored_artifacts)
            for problem in coverage["review_integrity_errors"][:30]:
                result.errors.append("逐檔規則完整性：" + problem)
            if coverage['missing_source_file_count']:
                result.errors.append(
                    f"應審查原始碼覆蓋不足："
                    f"{coverage['reviewed_source_file_count']}/{coverage['source_file_count']}；"
                    f"尚未審查 {coverage['missing_source_file_count']} 個檔案，"
                    f"依類型 {coverage['missing_by_type']}；"
                    f"例如 {coverage['missing_source_paths'][:8]}"
                )
        except (OSError, ValueError, KeyError, TypeError) as exc:
            result.errors.append(f"無法核對原始碼覆蓋率：{exc}")
    report_rules = {r['id']: r for r in data['rules']}
    if set(report_rules) != set(master):
        result.errors.append('report.rules 必須精確涵蓋規則主檔的 70 個 ID')
    for rid, r in report_rules.items():
        if rid in master and (r['title'] != master[rid]['title'] or r['category'] != master[rid]['category']):
            result.errors.append(f'{rid}: 報告規則名稱或類別與規則主檔不一致')
    master_doc = load_json(rules_path)
    if isinstance(master_doc, dict):
        current_version = master_doc.get('ruleset_version')
        assessment_version = assessment['ruleset_version']
        if data.get('current_ruleset_version') not in (None, current_version):
            result.errors.append('current_ruleset_version 與實際規則主檔版本不一致')
        if assessment_version == '2.0.0-rc1' and current_version == '2.0.0':
            result.warnings.append(
                'assessment.json 來自 2.0.0-rc1：保留既有審查進度及 Finding；'
                '新增規範對照仍須按真實證據補查，不得視為已完成。'
            )
        elif assessment_version != current_version:
            result.errors.append('assessment.ruleset_version 與 rules.json 的規則版本不符')

    result.errors.extend(completion_errors(assessment['checks'], allow_demo=allow_demo))
    if not allow_demo:
        result.errors.extend(decision_quality_errors(assessment['checks'], source_root=source_root))
    if 'system_baseline' in data:
        result.errors.extend(validate_system_baseline(data['project'], data['system_baseline']))
    if 'web_guide_v32' in data:
        result.errors.extend(validate_web_guide_index(list(master.values()), data['web_guide_v32']))
    if 'web_guide_v32_appendix1' in data:
        result.errors.extend(validate_appendix1(data['project'], list(master.values()), data['web_guide_v32_appendix1']))
    if 'web_guide_v32_appendix3' in data:
        result.errors.extend(validate_appendix3(list(master.values()), data['web_guide_v32_appendix3']))
    checks = {c['id']: c for c in assessment['checks']}
    if len(checks) != 70 or set(checks) != set(master):
        result.errors.append('assessment.checks 必須包含 70 個不重複且與規則主檔相符的 ID')
    # 安全等級初判證據只能引用已完成檢核的真實審查路徑。
    preliminary = data['project'].get('security_level_assessment')
    if preliminary:
        inspected = {
            str(path).replace('\\', '/')
            for check in assessment['checks'] if check.get('execution', {}).get('state') == 'completed'
            for path in check.get('execution', {}).get('inspected_paths', [])
        }
        for ev in preliminary['evidence']:
            rel = ev['path'].replace('\\', '/')
            if rel not in inspected:
                result.errors.append(f'安全等級初判證據 {rel}: 不在已完成檢核的 inspected_paths')
            _verify_line(ev, '安全等級初判', source_root, result, strict_sources, source_encodings)
    # 個資初判線索亦只能引用確實已完成並讀取的來源檔。
    personal = data['project'].get('personal_data_assessment')
    if personal:
        inspected = {
            str(path).replace('\\\\', '/')
            for check in assessment['checks'] if check.get('execution', {}).get('state') == 'completed'
            for path in check.get('execution', {}).get('inspected_paths', [])
        }
        for ev in personal['evidence']:
            rel = ev['path'].replace('\\\\', '/')
            if rel not in inspected:
                result.errors.append(f'個資初判證據 {rel}: 不在已完成檢核的 inspected_paths')
            _verify_line(ev, '個資處理初判', source_root, result, strict_sources, source_encodings)
    findings = {f['id']: f for f in assessment['findings']}
    for f in assessment['findings']:
        fid = f['id']
        if not SAFE_ID_RE.fullmatch(fid):
            result.errors.append(f'{fid}: Finding ID 不適合用作 HTML 錨點')
        for cid in f['check_ids']:
            if cid not in checks:
                result.errors.append(f'{fid}: 不存在的檢核項目 {cid}')
            elif cid not in master:
                result.errors.append(f'{fid}: 不屬於目前規則主檔的項目 {cid}')
        if not any(checks.get(cid, {}).get('status') == 'fail' for cid in f['check_ids']):
            result.warnings.append(f'{fid}: 沒有關聯不符合的檢核項，請人工確認是否為資訊性建議')

    for c in assessment['checks']:
        for fid in c.get('finding_ids', []):
            if fid not in findings:
                result.errors.append(f'{c["id"]}: finding_ids 引用不存在的 {fid}')
            elif c['id'] not in findings[fid]['check_ids']:
                result.errors.append(f'{c["id"]}: {fid} 未反向列入該檢核編號')
        for e in c['evidence']:
            if e.get('kind') == 'source':
                _verify_line(e, c['id'], source_root, result, strict_sources, source_encodings)
            elif e.get('kind') in ('deployment', 'operating_record', 'policy') and not e.get('artifact_id'):
                result.errors.append(f'{c["id"]}: 外部證據缺少 artifact_id')
    for f in assessment['findings']:
        for e in f['evidence']:
            if e.get('kind') == 'source':
                _verify_line(e, f['id'], source_root, result, strict_sources, source_encodings)
            elif e.get('kind') in ('deployment', 'operating_record', 'policy') and not e.get('artifact_id'):
                result.errors.append(f'{f["id"]}: 外部證據缺少 artifact_id')

    exceptions = assessment.get('exceptions', [])
    ex_ids = [e['id'] for e in exceptions]
    if len(ex_ids) != len(set(ex_ids)):
        result.errors.append('exception ID 重複')
    if len(findings) != len(assessment['findings']):
        result.errors.append('finding ID 重複')
    try:
        from datetime import date
        assessed = date.fromisoformat(assessment['assessment_date'])
        for e in exceptions:
            if e['rule_id'] not in master:
                result.errors.append(f'例外 {e["id"]}: 規則 ID 不存在')
            if date.fromisoformat(e['expires_on']) < assessed:
                result.errors.append(f'例外 {e["id"]}: 在審查日期已過期')
    except (ValueError, KeyError) as exc:
        result.errors.append(f'例外日期資訊錯誤：{exc}')
    exc_index = set(ex_ids)
    for c in assessment['checks']:
        if c.get('exception_id') and c['exception_id'] not in exc_index:
            result.errors.append(f'{c["id"]}: exception_id 不存在')

    pres = data['presentation']
    for g in pres.get('priorities', []):
        for fid in g['finding_ids']:
            if fid not in findings:
                result.errors.append(f'改善優先順序 {g["label"]}: 不存在的 {fid}')
    for fid, extra in pres.get('finding_details', {}).items():
        if fid not in findings:
            result.errors.append(f'finding_details: 不存在的 {fid}')
            continue
        for loc in extra.get('locations', []):
            _verify_line(loc, fid + ' 顯示位置', source_root, result, strict_sources, source_encodings)
            supported = any(
                e.get('kind') == 'source' and e.get('path', '').replace('\\', '/') == loc['path'].replace('\\', '/')
                and e.get('line_start', 0) <= loc['line_start']
                and e.get('line_end', 0) >= loc['line_end']
                for e in findings[fid]['evidence']
            )
            if not supported:
                (result.warnings if pres.get('demo') else result.errors).append(
                    f'{fid}: 顯示位置 {loc["path"]}:{loc["line_start"]}-{loc["line_end"]} 未被 Finding 原始證據涵蓋'
                )
    # Before 程式碼須與來源證據相符；標示 redacted 的截圖／遮蔽摘錄無法逐字驗證。
    for fid, extra in pres.get('finding_details', {}).items():
        snippet = extra.get('before_code', '').strip()
        if not snippet or fid not in findings:
            continue
        sources = [e for e in findings[fid]['evidence'] if e.get('kind') == 'source' and e.get('path')]
        if not sources:
            if not pres.get('demo'):
                result.errors.append(f'{fid}: Before 程式碼缺少來源證據')
            continue
        if source_root is not None:
            normalized = textwrap.dedent(snippet).strip().replace('\r\n', '\n')
            candidates = []
            for ev in sources:
                if ev.get('redacted'):
                    continue
                path = ev['path'].replace('\\', '/')
                resolved = (source_root.resolve() / path).resolve()
                if not resolved.is_relative_to(source_root.resolve()) or not resolved.is_file():
                    continue
                try:
                    lines = read_source_text(resolved, source_encodings)[0].splitlines()
                    candidate = '\n'.join(lines[ev['line_start']-1:ev['line_end']])
                    candidates.append(candidate)
                except (OSError, UnicodeError, KeyError):
                    continue
            if candidates and not any(normalized in textwrap.dedent(c).strip() for c in candidates):
                (result.errors if strict_sources else result.warnings).append(
                    f'{fid}: Before 程式碼與已引用的來源檔行號內容不一致（遮蔽內容請於 evidence.redacted 標示）'
                )
            if not candidates:
                if all(e.get('redacted') for e in sources):
                    result.warnings.append(f'{fid}: Before 程式碼來源已遮蔽，無法進行文字一致性驗證')
                else:
                    (result.errors if strict_sources else result.warnings).append(
                        f'{fid}: 沒有可讀的未遮蔽來源片段，無法核對 Before 程式碼'
                    )
    # 核對實際審查路徑與自動計算的統計，禁止手動造假計數。
    if source_root is not None and not allow_demo:
        try:
            actual_scope = build_scope_inventory(assessment, source_root, ignored_artifacts=ignored_artifacts)
            if 'scope_inventory' in data and data['scope_inventory'] != actual_scope:
                result.errors.append('scope_inventory 與實際來源／inspected_paths 不一致')
            if not actual_scope['reviewed_files'] and not pres.get('demo'):
                result.warnings.append('尚無 execution.inspected_paths，不能宣稱已審查全部檔案')
            if actual_scope['declared_project_count'] is None and not pres.get('demo'):
                result.warnings.append('尚未提供 scope_details.projects，無法確認審查專案數')
        except (ValueError, OSError) as exc:
            result.errors.append(f'審查範圍或檔案明細無法驗證：{exc}')
    elif 'scope_inventory' in data:
        result.warnings.append('未提供 --source-root，無法核對 scope_inventory')
    if pres.get('demo') and not allow_demo:
        result.errors.append('演示資料不可當成正式報告；測試時須指定 --allow-demo')
    if not pres.get('demo') and assessment['git_revision'].strip('0') == '':
        result.errors.append('正式報告不得使用全零 Git Revision')
    if source_root is None and not pres.get('demo'):
        result.warnings.append('未提供 --source-root；來源檔存在性與行號尚未實際核對')
    if not pres.get('methods'):
        result.warnings.append('未提供實際執行的審查方法')
    if not pres.get('limitations'):
        result.warnings.append('未提供審查限制，應由審查人員確認')
    return result


def safe_json_text(data: dict[str, Any]) -> str:
    # 不允許 </script> 等資料提前結束 JSON Script；同時避免 HTML 實體與特殊行分隔符。
    return (json.dumps(data, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
            .replace('&', r'\u0026').replace('<', r'\u003c').replace('>', r'\u003e')
            .replace('\u2028', r'\u2028').replace('\u2029', r'\u2029'))


def render_html(template: str, data: dict[str, Any]) -> str:
    matches = list(SLOT_RE.finditer(template))
    if len(matches) != 1:
        raise ValueError('HTML 模板必須且只能包含一個 report-data JSON Script')
    m = matches[0]
    if m.group(2).strip() != '__REPORT_DATA_JSON__':
        raise ValueError('HTML 模板 JSON 區塊必須為 __REPORT_DATA_JSON__，不得重複使用已填資料的報告')
    return template[:m.start(2)] + safe_json_text(data) + template[m.end(2):]


class _ReportHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.capturing = False
        self.payloads = []
        self.ids = []
        self.hash_links = []
        self.external_assets = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if a.get('id'):
            self.ids.append(a['id'])
        if tag == 'script' and a.get('id') == 'report-data':
            if a.get('type') != 'application/json':
                self.external_assets.append('report-data Script 型別錯誤')
            self.capturing = True
            self.payloads.append('')
        if a.get('src') or (tag == 'link' and a.get('href')):
            self.external_assets.append(f'{tag}: 外部資源引用')
        if tag in ('iframe', 'object', 'embed'):
            self.external_assets.append(f'{tag}: 非必要嵌入元素')
        if tag == 'a' and str(a.get('href', '')).startswith('#'):
            self.hash_links.append(a['href'][1:])

    def handle_data(self, data):
        if self.capturing:
            self.payloads[-1] += data

    def handle_endtag(self, tag):
        if tag == 'script' and self.capturing:
            self.capturing = False


def extract_html_report(html: str) -> tuple[dict[str, Any], _ReportHTML]:
    parser = _ReportHTML()
    parser.feed(html)
    parser.close()
    if len(parser.payloads) != 1:
        raise ValueError(f'HTML 須包含且僅包含一份報告 JSON（目前 {len(parser.payloads)} 份）')
    return json.loads(parser.payloads[0]), parser


def validate_html(html: str, data: dict[str, Any], template: str | None = None) -> Result:
    result = Result()
    try:
        extracted, tree = extract_html_report(html)
    except (ValueError, json.JSONDecodeError) as exc:
        result.errors.append(f'HTML JSON 無法讀取：{exc}')
        return result
    if extracted != data:
        result.errors.append('HTML 內嵌資料與 report.json 不一致')
    essential = {'summary', 'high', 'priority', 'strengths', 'checklist', 'findings', 'scope',
                 'stFilter', 'sevFilter', 'themeToggle', 'report-data', 'statusStats',
                 'severityStats', 'checklistContent', 'findingDetails', 'owasp2025Content', 'systemBaselineContent', 'webGuideContent', 'webAppendixContent', 'webHeadersContent'}
    if not essential.issubset(set(tree.ids)):
        result.errors.append('HTML 缺少必要節點：' + ', '.join(sorted(essential - set(tree.ids))))
    for link in tree.hash_links:
        if link not in tree.ids:
            result.errors.append(f'HTML 內部錨點 #{link} 不存在')
    if tree.external_assets:
        result.errors.extend(tree.external_assets)
    if template is not None:
        try:
            expected = render_html(template, data)
            if expected != html:
                result.errors.append('HTML 與固定模板不一致，或報告資料遭非預期修改')
        except ValueError as exc:
            result.errors.append(f'模板錯誤：{exc}')
    # 僅檢查版型本身；JSON 字串可能合法包含 CSS 範例（不可誤認為外部依賴）。
    html_without_data = SLOT_RE.sub(r'\1__OMITTED__\3', html)
    if '@import' in html_without_data or re.search(r'url\s*\(\s*["\']?https?://', html_without_data, re.IGNORECASE):
        result.errors.append('HTML 版型含外部 CSS 或 URL 依賴')
    return result
