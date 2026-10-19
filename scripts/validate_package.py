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
ids=[r['id'] for r in j['rules']]
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

print(f"規則數：{len(ids)}；分類：{dict(counts)}；已填 ASVS 關聯之規則：{sum(bool(r['references']['technical_requirements']) for r in j['rules'])}")
if errors:
 print('\n'.join('ERROR: '+e for e in errors),file=sys.stderr)
 sys.exit(1)
print('PASS: package verified')
