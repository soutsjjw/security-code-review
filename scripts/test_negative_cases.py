#!/usr/bin/env python3
"""Regression checks for invalid assessment inputs; no source project required."""
import copy,json,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
validator=ROOT/'scripts/validate_assessment.py'
base=json.loads((ROOT/'examples/assessment.example.json').read_text('utf-8'))

def run_case(obj, expected_ok, label):
 with tempfile.TemporaryDirectory() as d:
  f=Path(d)/'assessment.json';f.write_text(json.dumps(obj,ensure_ascii=False),encoding='utf-8')
  p=subprocess.run([sys.executable,str(validator),str(f)],capture_output=True,text=True)
  if (p.returncode==0)!=expected_ok:
   print('FAILED',label,p.stdout,p.stderr);sys.exit(1)
  print('PASS',label)

run_case(base,True,'70 entries in Review, format only')
t=copy.deepcopy(base);t['checks'][0]['id']=t['checks'][1]['id'];run_case(t,False,'duplicate/missing ID must fail')
t=copy.deepcopy(base);t['checks'][0]['status']='pass';run_case(t,False,'Pass without evidence must fail')
t=copy.deepcopy(base);t['checks'][0]['status']='fail';run_case(t,False,'Fail without evidence must fail')
t=copy.deepcopy(base);t['checks'][0]['status']='na';t['checks'][0]['applicability_reason']='無';run_case(t,False,'N/A without clear reason must fail')
t=copy.deepcopy(base);t['exceptions']=[{'id':'EX-1','rule_id':'AU-02','approver':'資安主管','accepted_by':'系統擁有者','expires_on':'2020-01-01','compensating_controls':'MFA','justification':'測試'}];run_case(t,False,'expired exception must fail')
