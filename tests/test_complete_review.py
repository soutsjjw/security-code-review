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
from review_fixture import make_file_review


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
                    'inspected_paths': ['IdentityService.cs'] if c['id'] in ('AC-01', 'AU-01') else []
                }
                c['decision_reason'] = f"已完成 {c['id']} 的測試資料處理；因缺少外部環境佐證維持 review"
                if c['id'] not in ('AC-01', 'AU-01'):
                    c['evidence'] = [{
                        'kind': 'other', 'description': '這是整合測試的人工合成證據，不是對實際系統的資安判定',
                        'collected_on': '2026-10-18', 'source_version': 'fixture'
                    }]
            (target / 'IdentityService.cs').write_bytes('// 中文註解：身份檢查\n'.encode('cp950'))
            a['file_reviews'] = [make_file_review(target, 'IdentityService.cs', ['AC-01', 'AU-01'])]
            a['scope_details'] = {'projects': [{'name': 'Identity', 'path': '.'}],
                                  'excluded_paths': [{'path': 'bin', 'reason': '建置輸出'}]}
            (target / 'bin').mkdir()
            (target / 'bin' / 'generated.dll').write_bytes(b'compiled')
            # 不應把第三個規則 AC-02 也無條件關聯到此檔。
            a['checks'][0]['execution']['inspected_paths'] = ['IdentityService.cs']
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
            self.assertEqual(report_data['current_ruleset_version'], '2.0.0')
            self.assertIn(report_data['project']['personal_data'], ('是', '待確認'))
            self.assertEqual(report_data['presentation']['overall_risk']['level'], 'review')
            self.assertTrue(report_data['presentation']['pending_information'])
            self.assertIn('執行介面無法辨識', report_data['presentation']['reviewer'])
            self.assertNotIn('初步研判佐證', (output / 'CodeReview_20261018.html').read_text('utf-8'))
            inv = report_data['scope_inventory']
            self.assertEqual(inv['reviewed_file_count'], 1)
            self.assertEqual(inv['reviewed_project_count'], 1)
            self.assertEqual(inv['reviewed_files'][0]['check_ids'],
                             ['AC-01', 'AU-01'])
            self.assertGreaterEqual(inv['excluded_file_count'], 1)
            self.assertIn('審查檔案明細', (output / 'CodeReview_20261018.html').read_text('utf-8'))
            self.assertFalse((SKILL_ROOT / 'reports').exists())

            # 新增一個未讀來源檔；即使 70 項皆 completed 也必須拒絕重新交付。
            (target / 'NotReviewed.cs').write_text('// 尚未審查', encoding='utf-8')
            old_report = (output / 'report.json').read_bytes()
            rejected = subprocess.run(cmd, cwd=base, capture_output=True, text=True)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn('原始碼審查覆蓋不足', rejected.stderr)
            self.assertEqual((output / 'report.json').read_bytes(), old_report)

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
