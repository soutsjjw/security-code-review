#!/usr/bin/env python3
import json,sys,re
from pathlib import Path
from datetime import date
from jsonschema import Draft202012Validator,FormatChecker

ROOT=Path(__file__).resolve().parent.parent
if len(sys.argv)!=2:
 print('Usage: python scripts/validate_assessment.py assessment.json');sys.exit(2)
p=Path(sys.argv[1])
data=json.loads(p.read_text('utf-8'))
schema=json.loads((ROOT/'schemas/assessment.schema.json').read_text('utf-8'))
errs=[e.message for e in Draft202012Validator(schema,format_checker=FormatChecker()).iter_errors(data)]
valid={r['id'] for r in json.loads((ROOT/'rules.json').read_text('utf-8'))['rules']}
checks=data.get('checks',[]); ids=[c.get('id') for c in checks]
if set(ids)!=valid or len(ids)!=len(valid): errs.append('checks ID must cover 70 rules exactly once')
finding_ids={f.get('id') for f in data.get('findings',[])}
if len(finding_ids)!=len(data.get('findings',[])): errs.append('duplicate finding IDs')
exc_ids={x.get('id') for x in data.get('exceptions',[])}
if len(exc_ids)!=len(data.get('exceptions',[])): errs.append('duplicate exception IDs')
for c in checks:
 rid=c.get('id','?');s=c.get('status')
 if s in ('pass','fail') and not c.get('evidence'):errs.append(f'{rid}: {s} without evidence')
 if s=='na' and len(c.get('applicability_reason','').strip())<12:errs.append(f'{rid}: na needs explicit rationale')
 if s=='review' and '已符合' in c.get('decision_reason',''):errs.append(f'{rid}: review with pass claims')
 for fid in c.get('finding_ids',[]):
  if fid not in finding_ids:errs.append(f'{rid}: missing referenced finding {fid}')
 for e in c.get('evidence',[]):
  if e.get('kind')=='source' and not (e.get('path') and e.get('line_start') and e.get('line_end')):
   errs.append(f'{rid}: source evidence requires path and line range')
  if e.get('line_start') and e.get('line_end') and e['line_start']>e['line_end']:
   errs.append(f'{rid}: invalid line range')
  if e.get('kind') in ('deployment','operating_record','policy') and not e.get('artifact_id'):
   errs.append(f'{rid}: external evidence needs artifact_id')
for f in data.get('findings',[]):
 for i in f.get('check_ids',[]):
  if i not in valid:errs.append(f"finding {f.get('id')}: unknown check {i}")
for e in data.get('exceptions',[]):
 if e.get('rule_id') not in valid:errs.append(f"exception {e.get('id')}: unknown rule")
 try:
  if date.fromisoformat(e['expires_on'])<date.fromisoformat(data['assessment_date']):errs.append(f"exception {e['id']}: expired")
 except (KeyError,ValueError):pass
print(f"70 項檢核：{len(checks)}；發現：{len(finding_ids)}；例外：{len(exc_ids)}")
if errs:
 for e in errs:print('ERROR:',e,file=sys.stderr)
 sys.exit(1)
print('PASS: assessment verified')
