#!/usr/bin/env python3
from pathlib import Path
from collections import Counter
import json,sys
import yaml
from jsonschema import Draft202012Validator

ROOT=Path(__file__).resolve().parent.parent
j=json.loads((ROOT/'rules.json').read_text('utf-8'))
y=yaml.safe_load((ROOT/'rules.yaml').read_text('utf-8'))
s=json.loads((ROOT/'schemas/rules.schema.json').read_text('utf-8'))
errors=[]
errors += [e.message for e in Draft202012Validator(s).iter_errors(j)]
if j!=y:errors.append('rules.json and rules.yaml mismatch')
if j.get('ruleset_version')!='2.0.0' or j.get('release_status')!='stable':
 errors.append('70-rule catalog must use stable v2.0.0 release metadata')
if j.get('release_date')!='2026-10-20':
 errors.append('70-rule catalog must record its stable release date')
if any(r.get('rule_version')!='2.0.0' for r in j['rules']):
 errors.append('70 rules must all carry stable v2.0.0 rule_version')
assessment_schema=json.loads((ROOT/'schemas/assessment.schema.json').read_text('utf-8'))
if assessment_schema['properties']['ruleset_version'].get('enum')!=['2.0.0','2.0.0-rc1']:
 errors.append('assessment schema must support stable v2.0.0 and prior rc1 progress')

ids=[r['id'] for r in j['rules']]
from review_safety import rule_scopes
try:
 scopes=rule_scopes()
 if set(scopes)!=set(ids) or any(mode not in ('local','cross_file','project') for mode in scopes.values()):
  errors.append('P0 review scope policy must cover exact 70 rule IDs')
except (ValueError,OSError,KeyError,TypeError) as exc:
 errors.append(f'invalid P0 review scope policy: {exc}')
if len(ids)!=len(set(ids)):errors.append('duplicate rule IDs')
category_expected={'AC':8,'AU':10,'IN':8,'CR':6,'EH':6,'LG':10,'DP':4,'PD':8,'BC':7,'SI':3}
counts=Counter(r['category'] for r in j['rules'])
if dict(counts)!=category_expected: errors.append(f'categories mismatch {counts}')
for cat,n in category_expected.items():
 p=ROOT/'rules'/f'{cat}.yaml'
 if not p.exists():errors.append(f'missing {p}');continue
 yr=yaml.safe_load(p.read_text('utf-8'))
 if yr['rules']!=[r for r in j['rules'] if r['category']==cat]: errors.append(f'category diff {cat}')
for r in j['rules']:
 if r['applicability']['no_evidence']!='review':errors.append(f"{r['id']} unknown evidence policy differs")
 if not r['inspection']['search_targets']:errors.append(f"{r['id']} empty search targets")
 if r['risk']['default_severity']!='not_preassigned':errors.append(f"{r['id']} hard-coded severity")
 for ref in r['references']['technical_requirements']:
  if not ref['requirement_id'].startswith('v5.0.0-'):errors.append('unversioned ASVS reference')
  if ref['mapping_type']!='relevant_requirement_not_full_equivalence':errors.append('invalid mapping type')

# 判定方式是提示與完成品質契約，不預設弱點嚴重度，規則 ID 不得遺漏。
from review_decision import load_decision_matrix
try:
 matrix=load_decision_matrix()
 if set(matrix)!=set(ids):
  errors.append('review decision matrix must cover exact 70 rule IDs')
 for rid, guidance in matrix.items():
  if not all(isinstance(guidance.get(field),str) and guidance[field].strip()
             for field in ('pass_condition','expected_evidence','manual_boundary','applicability')):
   errors.append(f'{rid}: decision matrix missing specific review criteria')
except (OSError,ValueError,KeyError,TypeError) as exc:
 errors.append(f'invalid review decision matrix: {exc}')

# TACERT V2 補充檢核必須與文件段落及原 70 項保持一致。
checklist=yaml.safe_load((ROOT/'standards/tacert-v2-checklist.yaml').read_text('utf-8'))
entries=checklist.get('checks',[])
tacert_ids=[c.get('id') for c in entries]
if len(entries)!=39 or len(tacert_ids)!=len(set(tacert_ids)):
 errors.append('TACERT V2 checks must be 39 unique entries')
for prefix,expected in [('R',12),('D',14),('P',13)]:
 if sum(x.startswith('TACERT-V2-'+prefix) for x in tacert_ids)!=expected:
  errors.append(f'TACERT V2 {prefix} count mismatch')
for c in entries:
 if c.get('verification_mode') not in ('source','hybrid','external'):
  errors.append(f"TACERT V2 invalid verification_mode: {c.get('id')}")
 if not c.get('review_steps') or not c.get('expected_evidence') or not c.get('pdf_page'):
  errors.append(f"TACERT V2 incomplete content: {c.get('id')}")
 if not c.get('related_rule_ids') or not set(c['related_rule_ids']).issubset(set(ids)):
  errors.append(f"TACERT V2 unknown mapped rule: {c.get('id')}")


# OWASP Top 10:2025 為十個風險分類，不是十個合規要求。
owasp=yaml.safe_load((ROOT/'standards/owasp-top10-2025.yaml').read_text('utf-8'))
categories=owasp.get('categories', [])
if owasp.get('version')!='2025' or len(categories)!=10:
 errors.append('OWASP Top 10 2025 must have ten official categories')
if [c.get('id') for c in categories]!=[f'A{i:02d}:2025' for i in range(1,11)]:
 errors.append('OWASP Top 10 2025 ID/order mismatch')
for cat in categories:
 if cat.get('mapping_type')!='related_risk_not_full_coverage':
  errors.append(f"OWASP category is not marked as partial mapping: {cat.get('id')}")
 if not cat.get('review_steps') or not cat.get('coverage_gap'):
  errors.append(f"OWASP missing review guidance or coverage gap: {cat.get('id')}")
 if not cat.get('url','').startswith('https://top10.owasp.org/2025/'):
  errors.append(f"OWASP invalid official URL: {cat.get('id')}")
 if not cat.get('related_rule_ids') or not set(cat['related_rule_ids']).issubset(set(ids)):
  errors.append(f"OWASP unknown mapped rule: {cat.get('id')}")
a01=next((cat for cat in categories if cat.get('id')=='A01:2025'), {})
a10=next((cat for cat in categories if cat.get('id')=='A10:2025'), {})
if 'IN-08' not in a01.get('related_rule_ids',[]) or 'IN-08' in a10.get('related_rule_ids',[]):
 errors.append('OWASP 2025 SSRF belongs to A01, not A10')


# 確保第二層 V1.3 80 項來源編目與舊版 70 項規則並行而不混淆。
from system_baseline import load_catalog
baseline_controls = load_catalog()
baseline_ids = {c["id"] for c in baseline_controls}
if len(baseline_ids) != 80:
 errors.append('TW baseline V1.3 must have 80 unique controls')
domain_counts = Counter(c['domain'] for c in baseline_controls)
expected_domains = {'存取控制':14,'事件日誌與可歸責性':13,'營運持續計畫':8,
                    '識別與鑑別':12,'系統與服務獲得':19,'系統與通訊保護':5,'系統與資訊完整性':9}
if dict(domain_counts) != expected_domains:
 errors.append(f'TW baseline domains mismatch: {domain_counts}')
for control in baseline_controls:
 if control['id'] != 'TW-SB-' + control['source_section']:
  errors.append(f"TW baseline source ID mismatch: {control['id']}")
 if not set(control['related_rule_ids']).issubset(set(ids)):
  errors.append(f"TW baseline references unknown 70-rule ID: {control['id']}")

# V3.2 Web 指引應包含第 4 章 29 類/35 個細部條次，並嚴格排除 Java/PHP 專屬範例。
from web_guide import load_web_guide
guide=load_web_guide(j['rules'])
guide_categories=guide['controls']
guide_topics=[t for c in guide_categories for t in c['implementation_topics']]
if len(guide_categories)!=29 or len(guide_topics)!=35:
 errors.append('NICS Web guide V3.2 must have 29 categories and 35 detailed topics')
if guide['scope']['excluded_implementation_technologies']!=['Java','PHP']:
 errors.append('NICS Web guide must exclude Java and PHP implementation examples')
for obj in [*guide_categories,*guide_topics]:
 focus=obj['review_focus'].lower()
 if 'servlet' in focus or 'jsp' in focus or 'php' in focus:
  errors.append(f"NICS V3.2 contains excluded implementation language hint: {obj['id']}")
header=next((t for t in guide_topics if t['source_section']=='4.5.3.4'),None)
if not header or header['pdf_page']!=207 or not {'CR-05','CR-06'}.issubset(header['related_rule_ids']):
 errors.append('NICS V3.2 HTTP security header crosswalk missing')

# NICS WEB V3.2 附件1 的55項細則、27類與分級檢核結果皆須來自附件來源。
from web_appendix1 import load_appendix1
webappendix=load_appendix1(j['rules'])
webappendix_ids=[e['id'] for e in webappendix['checks']]
if len(webappendix_ids)!=55 or len(set(webappendix_ids))!=55:
 errors.append('WEB Appendix1 must contain exactly 55 unique checks')
if webappendix['category_count']!=27 or webappendix['level_counts']!={'普':33,'中':44,'高':55}:
 errors.append('WEB Appendix1 category or level counts mismatch')
if any(e['verification_mode'] not in ('source','hybrid','external') for e in webappendix['checks']):
 errors.append('WEB Appendix1 invalid verification mode')
if any(e['parent_section'] in ('4.4.5','4.7.1') for e in webappendix['checks']):
 errors.append('WEB Appendix1 must not invent omitted V3.2 categories')
if any(e['id']=='NICS-WEB-4.5.3.4' for e in webappendix['checks']):
 errors.append('WEB Appendix1 must not misrepresent main-guide HTTP header requirement')

# V3.2 附件3的六項標頭必須明確屬於 CR-05，且不會自動從程式碼推斷 Pass。
from web_headers import load_headers, build_appendix3
headers_doc=load_headers(j['rules'])
headers_checks=headers_doc['checks']
if len(headers_checks)!=6 or len({item['header'] for item in headers_checks})!=6:
 errors.append('WEB Appendix3 must have 6 unique HTTP headers')
if any('CR-05' not in item['related_rule_ids'] for item in headers_checks):
 errors.append('WEB Appendix3 must map each header to CR-05')
if headers_doc['scope']['excluded_implementation_technologies'] != ['Java','PHP']:
 errors.append('WEB Appendix3 must exclude Java/PHP implementations')
if build_appendix3(j['rules'])['status_counts'] != {'not_assessed':6}:
 errors.append('WEB Appendix3 must default to unassessed, never Pass')
csp=next((item for item in headers_checks if item['header']=='Content-Security-Policy'),{})
if not any('unsafe-inline' in v and 'unsafe-eval' in v for v in csp.get('implementation_cautions',[])):
 errors.append('WEB Appendix3 must highlight weak CSP example')
# P5：文件拆分後仍須確保 Skill 能按 --detail-id 找到每個標準的查核指引。
from validate_skill_docs import documentation_errors
errors.extend(documentation_errors(ROOT))

print(f"規則數：{len(ids)}；分類：{dict(counts)}；已填 ASVS 關聯之規則：{sum(bool(r['references']['technical_requirements']) for r in j['rules'])}")
if errors:
 print('\n'.join('ERROR: '+e for e in errors),file=sys.stderr)
 sys.exit(1)
print('PASS: package verified')
