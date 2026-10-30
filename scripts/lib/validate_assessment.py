#!/usr/bin/env python3
import json, sys
from pathlib import Path
from datetime import date
from jsonschema import Draft202012Validator,FormatChecker
from review_completion import completion_errors
from review_decision import decision_quality_errors
from assessment_consistency import consistency_errors,consistency_warnings,finding_quality_issues
from source_coverage import build_source_coverage
from scope_inventory import scope_project_issues
from review_safety import safety_errors

ROOT=Path(__file__).resolve().parents[2]


def main(argv=None):
 args=sys.argv[1:] if argv is None else list(argv)
 if not args or args[0].startswith('--'):
  print('Usage: python scripts/validate_assessment.py assessment.json [--allow-demo] [--source-root TARGET]');sys.exit(2)
 p=Path(args[0])
 allow_demo='--allow-demo' in args[1:]
 source_root=None
 if '--source-root' in args[1:]:
  try:
   source_root=Path(args[args.index('--source-root')+1])
  except IndexError:
   print('ERROR: --source-root 缺少目錄',file=sys.stderr);sys.exit(2)
 if not allow_demo and source_root is None:
  print('ERROR: 正式審查驗證必須提供 --source-root，以檢查 file_reviews 與來源雜湊',file=sys.stderr);sys.exit(2)
 data=json.loads(p.read_text('utf-8'))
 schema=json.loads((ROOT/'schemas/assessment.schema.json').read_text('utf-8'))
 errs=[e.message for e in Draft202012Validator(schema,format_checker=FormatChecker()).iter_errors(data)]
 valid={r['id'] for r in json.loads((ROOT/'rules.json').read_text('utf-8'))['rules']}
 checks=data.get('checks',[]); ids=[c.get('id') for c in checks]
 errs.extend(completion_errors(checks, allow_demo=allow_demo))
 if not allow_demo:
  errs.extend(decision_quality_errors(checks, source_root=source_root))
 if not allow_demo:
  errs.extend(consistency_errors(data))
  for w in consistency_warnings(data):print('WARNING:',w,file=sys.stderr)
 if source_root is not None and not allow_demo:
  errs.extend(safety_errors(source_root,data))
  se,sw=scope_project_issues(data,source_root)
  errs.extend(se)
  for w in sw:print('WARNING:',w,file=sys.stderr)
  fe,fw=finding_quality_issues(data,source_root)
  errs.extend(fe)
  for w in fw:print('WARNING:',w,file=sys.stderr)
  try:
   coverage=build_source_coverage(data,source_root)
   errs.extend(coverage['review_integrity_errors'][:30])
   if coverage['missing_source_file_count']:
    errs.append(f"逐檔來源覆蓋不足：{coverage['reviewed_source_file_count']}/{coverage['source_file_count']}")
  except (OSError,ValueError,KeyError,TypeError) as exc:
   errs.append(f"逐檔佐證驗證失敗：{exc}")
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
 print(f"70 項檢核：{len(checks)}；已執行：{sum(c.get('execution',{}).get('state')=='completed' for c in checks)}；發現：{len(finding_ids)}；例外：{len(exc_ids)}")
 if errs:
  for e in errs:print('ERROR:',e,file=sys.stderr)
  sys.exit(1)
 print('PASS: assessment verified')
 return 0


if __name__ == '__main__':
 raise SystemExit(main())
