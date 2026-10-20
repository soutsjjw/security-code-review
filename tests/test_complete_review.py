"""驗證在被審查專案根目錄之外安裝 Skill 時仍能正確輸出。"""
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_ROOT / 'scripts'))
from report_common import load_json


class CompleteReviewTests(unittest.TestCase):
    def test_target_outside_skill_generates_reports(self):
        example = load_json(SKILL_ROOT / 'examples/report-data.example.json')
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            target = base / 'another-project'
            target.mkdir()
            output = target / 'reports/security-code-review'
            output.mkdir(parents=True)
            a = copy.deepcopy(example['assessment'])
            a['project_id'] = 'another-project'
            a['git_revision'] = 'a' * 40
            a['assessment_date'] = '2026-10-18'
            # 測試流程以人工合成的完成狀態驗證驗收管線，並非實際安全掃描。
            for c in a['checks']:
                c['execution'] = {
                    'state': 'completed', 'methods': ['integration_fixture'],
                    'summary': f"整合測試依序驗證 {c['id']} 的審查流程與報告產生",
                    'inspected_paths': []
                }
                c['decision_reason'] = f"已完成 {c['id']} 的測試資料處理；因缺外部環境佐證維持 review"
            (target / 'IdentityService.cs').write_bytes('// 中文註解：身份檢查\n'.encode('cp950'))
            a['scope_details'] = {'projects': [{'name': 'Identity', 'path': '.'}],
                                  'excluded_paths': [{'path': 'bin', 'reason': '建置輸出'}]}
            (target / 'bin').mkdir()
            (target / 'bin' / 'generated.dll').write_bytes(b'compiled')
            a['checks'][0]['execution']['inspected_paths'] = ['IdentityService.cs']
            a['checks'][1]['execution']['inspected_paths'] = ['IdentityService.cs']
            a['checks'][0]['evidence'] = [{
                'kind': 'source', 'description': '核對 CP950 原始碼的來源檔與行號',
                'collected_on': '2026-10-18', 'source_version': 'test',
                'path': 'IdentityService.cs', 'line_start': 1, 'line_end': 1
            }]
            (output / 'assessment.json').write_text(json.dumps(a, ensure_ascii=False), encoding='utf-8')
            p = {'name':'整合測試系統', 'language_framework':'測試程式語言'}
            (output / 'project.json').write_text(json.dumps(p, ensure_ascii=False), encoding='utf-8')
            (output / 'presentation.json').write_text(json.dumps({
                'methods':['唯讀來源檢查（測試資料）'],
                'limitations':['測試資料均為待確認；不是實際審查']
            }, ensure_ascii=False), encoding='utf-8')
            cmd = [sys.executable, str(SKILL_ROOT / 'scripts/complete_review.py'), '--target', str(target)]
            run = subprocess.run(cmd, cwd=base, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            rerun = subprocess.run(cmd, cwd=base, capture_output=True, text=True)
            self.assertEqual(rerun.returncode, 0, rerun.stdout + rerun.stderr)
            self.assertTrue((output / 'CodeReview_20261018.html').is_file())
            self.assertTrue((output / 'report.json').is_file())
            report_data = json.loads((output / 'report.json').read_text('utf-8'))
            self.assertEqual(report_data['project']['name'], '整合測試系統')
            inv = report_data['scope_inventory']
            self.assertEqual(inv['reviewed_file_count'], 1)
            self.assertEqual(inv['reviewed_project_count'], 1)
            self.assertEqual(inv['reviewed_files'][0]['check_ids'],
                             sorted([a['checks'][0]['id'], a['checks'][1]['id']]))
            self.assertGreaterEqual(inv['excluded_file_count'], 1)
            self.assertIn('審查檔案明細', (output / 'CodeReview_20261018.html').read_text('utf-8'))
            self.assertFalse((SKILL_ROOT / 'reports').exists())

    def test_missing_inputs_are_rejected_without_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            run = subprocess.run([sys.executable, str(SKILL_ROOT/'scripts/complete_review.py'), '--target', str(target)],
                                 cwd=target, capture_output=True, text=True)
            self.assertNotEqual(run.returncode, 0)
            self.assertFalse((target/'reports/security-code-review/report.json').exists())

    def test_rejects_skill_root_as_target(self):
        run = subprocess.run([sys.executable, str(SKILL_ROOT/'scripts/complete_review.py'), '--target', str(SKILL_ROOT)],
                             capture_output=True, text=True)
        self.assertNotEqual(run.returncode, 0)

    def test_rejects_output_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = subprocess.run([sys.executable, str(SKILL_ROOT/'scripts/complete_review.py'),
                                  '--target', str(tmp), '--output-dir', '../../outside'],
                                 capture_output=True, text=True)
            self.assertNotEqual(run.returncode, 0)

if __name__ == '__main__':
    unittest.main()
