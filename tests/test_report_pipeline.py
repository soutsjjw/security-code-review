"""報告產生器／驗證器端到端正負向測試。"""
import copy
import os
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE / 'scripts'))
from report_common import load_json, render_html, validate_data, validate_html, extract_html_report
from security_level import infer_security_level


class ReportingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.example = load_json(HERE / 'examples/report-data.example.json')
        cls.template = (HERE / 'templates/security-report.html').read_text('utf-8')

    def fresh(self):
        return copy.deepcopy(self.example)

    def test_source_reader_cli_automatic_legacy_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'IdentityService.cs'
            source.write_bytes('驗證失敗次數控制\n'.encode('cp950'))
            result = subprocess.run(
                [sys.executable, str(HERE / 'scripts/source_reader.py'),
                 '--source-root', str(root), '--path', source.name,
                 '--start', '1', '--end', '1'],
                text=True, capture_output=True, encoding='utf-8',
                env=dict(os.environ, PYTHONIOENCODING='cp950')
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('1: 驗證失敗次數控制', result.stdout)
            self.assertIn('WARN:', result.stderr)

    def test_source_reader_cli_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = subprocess.run(
                [sys.executable, str(HERE / 'scripts/source_reader.py'),
                 '--source-root', str(root), '--path', '../outside.cs'],
                text=True, capture_output=True, encoding='utf-8',
                env=dict(os.environ, PYTHONIOENCODING='cp950')
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('路徑不得超出受測專案', result.stderr)

    def test_source_reader_cli_rejects_absolute_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable, str(HERE / 'scripts/source_reader.py'),
                 '--source-root', tmp, '--path', 'C:/outside.cs'],
                text=True, capture_output=True, encoding='utf-8',
                env=dict(os.environ, PYTHONIOENCODING='cp950')
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('來源路徑必須是相對路徑', result.stderr)

    def test_mixed_source_encodings(self):
        variants = [('utf8.cs', 'utf-8'), ('bom.cs', 'utf-8-sig'),
                    ('utf16.cs', 'utf-16'), ('cp950.cs', 'cp950')]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for filename, encoding in variants:
                with self.subTest(encoding=encoding):
                    (root / filename).write_bytes('中文程式碼檢查\n'.encode(encoding))
                    data = self.fresh()
                    data['assessment']['checks'][0]['evidence'] = [{
                        'kind': 'source', 'description': '核對實際來源檔案的編碼與行號',
                        'collected_on': '2026-10-16', 'source_version': 'fixture',
                        'path': filename, 'line_start': 1, 'line_end': 1
                    }]
                    result = validate_data(data, allow_demo=True, source_root=root, strict_sources=True)
                    self.assertEqual(result.errors, [])
                    if encoding == 'cp950':
                        self.assertIn('cp950', ' '.join(result.warnings))

    def test_binary_source_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'broken.cs').write_bytes(b'\xff\x00\xff\x00')
            data = self.fresh()
            data['assessment']['checks'][0]['evidence'] = [{
                'kind': 'source', 'description': '不可讀的來源檔案須回報失敗',
                'collected_on': '2026-10-16', 'source_version': 'fixture',
                'path': 'broken.cs', 'line_start': 1, 'line_end': 1
            }]
            result = validate_data(data, allow_demo=True, source_root=root, strict_sources=True)
            self.assertIn('來源檔無法讀取', ' '.join(result.errors))

    def test_formal_pending_rejected(self):
        data = self.fresh()
        data['presentation']['demo'] = False
        data['assessment']['git_revision'] = 'a' * 40
        result = validate_data(data)
        self.assertIn('尚未完成實際檢核', ' '.join(result.errors))

    def test_formal_mass_placeholder_rejected(self):
        data = self.fresh()
        data['presentation']['demo'] = False
        data['assessment']['git_revision'] = 'a' * 40
        for c in data['assessment']['checks']:
            c['execution'] = {'state': 'completed', 'methods': ['source_review'],
                              'summary': '全部檢核使用相同的內容作為執行摘要，沒有各自查核紀錄'}
            c['decision_reason'] = '全部項目皆填寫相同內容，缺少逐項查核的區別與依據'
        result = validate_data(data)
        self.assertIn('共用相同結論', ' '.join(result.errors))

    def test_checklist_severity_and_applicability_are_separate(self):
        page = render_html(self.template, self.fresh())
        self.assertIn("'弱點等級','適用防護等級'", page)
        self.assertIn("const sevKeys=['critical','high','medium','low','info']", page)
        self.assertIn("asArray(f.check_ids).includes(r.id)", page)
        self.assertIn("const highest=order.find(level=>foundLevels.includes(level))", page)
        self.assertIn("沒有對應的已記錄弱點，不等於低風險", page)

    def test_positive_demo(self):
        data = self.fresh()
        self.assertFalse(validate_data(data, allow_demo=True).errors)
        page = render_html(self.template, data)
        self.assertEqual(validate_html(page, data, self.template).errors, [])
        recovered, _ = extract_html_report(page)
        self.assertEqual(recovered, data)

    def test_demo_requires_flag(self):
        self.assertIn('演示資料不可當成正式報告', ' '.join(validate_data(self.fresh()).errors))

    def test_no_evidence_fail(self):
        data = self.fresh()
        data['assessment']['checks'][0]['status'] = 'fail'
        self.assertTrue(validate_data(data, allow_demo=True).errors)

    def test_missing_rule(self):
        data = self.fresh()
        data['rules'].pop()
        self.assertTrue(validate_data(data, allow_demo=True).errors)

    def test_duplicate_check(self):
        data = self.fresh()
        data['assessment']['checks'][-1] = copy.deepcopy(data['assessment']['checks'][0])
        self.assertTrue(validate_data(data, allow_demo=True).errors)

    def test_canonical_rule_changed(self):
        data = self.fresh()
        data['rules'][0]['title'] = '被竄改規則名稱'
        self.assertIn('名稱或類別', ' '.join(validate_data(data, allow_demo=True).errors))

    def test_unknown_finding(self):
        data = self.fresh()
        data['presentation']['priorities'] = [{'label':'測試', 'finding_ids':['F-99']}]
        self.assertTrue(validate_data(data, allow_demo=True).errors)

    def test_script_injection_escaped(self):
        data = self.fresh()
        attack = '</script><script>window.attacked=true</script>'
        data['project']['name'] = attack
        page = render_html(self.template, data)
        self.assertNotIn(attack, page)
        self.assertIn(r'\u003c/script\u003e', page)
        extracted, _ = extract_html_report(page)
        self.assertEqual(extracted['project']['name'], attack)
        self.assertEqual(validate_html(page, data, self.template).errors, [])

    def test_tampered_html_rejected(self):
        data = self.fresh()
        page = render_html(self.template, data).replace('<h1>Code Review', '<h1>造假 Review', 1)
        self.assertTrue(validate_html(page, data, self.template).errors)

    def test_outside_source_path(self):
        data = self.fresh()
        data['assessment']['checks'][0]['evidence'] = [{
            'kind': 'source', 'description':'來源檔案安全性檢核',
            'collected_on':'2026-10-16','source_version':'test',
            'path':'../../etc/passwd','line_start':1,'line_end':1
        }]
        self.assertIn('跨出專案', ' '.join(validate_data(data, allow_demo=True).errors))

    def test_source_line_too_high_strict(self):
        data = self.fresh()
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root/'src').mkdir()
            (root/'src'/'one.cs').write_text('first\nsecond\n', encoding='utf-8')
            data['assessment']['checks'][0]['evidence'] = [{
                'kind': 'source', 'description':'確實存在的兩行原始碼',
                'collected_on':'2026-10-16','source_version':'test',
                'path':'src/one.cs','line_start':1,'line_end':99
            }]
            self.assertIn('超過檔案總行數', ' '.join(validate_data(data, allow_demo=True, source_root=root, strict_sources=True).errors))

    def test_valid_finding_and_code_location(self):
        data = self.fresh()
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root/'src').mkdir()
            (root/'src'/'one.cs').write_text('var value = input;\nreturn value;\n', encoding='utf-8')
            ev = {'kind':'source','description':'編排測試的程式碼位置','collected_on':'2026-10-16',
                  'source_version':'fixture','path':'src/one.cs','line_start':1,'line_end':2}
            data['assessment']['checks'][0].update(status='fail', evidence=[ev], finding_ids=['F-01'])
            data['assessment']['findings'] = [{
                'id':'F-01','title':'純測試問題','severity':'low','check_ids':['AC-01'],
                'impact':'測試用的影響說明','evidence':[ev], 'remediation':'僅供測試改善建議'
            }]
            data['presentation']['finding_details'] = {
                'F-01': {'locations':[{'path':'src/one.cs','line_start':1,'line_end':2}],
                         'description':'僅供版面測試','risk':'虛構情境',
                         'before_code':'var value = input;', 'after_code':'var value = safeInput;'}
            }
            data['presentation']['priorities'] = [{'label':'測試優先','finding_ids':['F-01']}]
            outcome = validate_data(data, allow_demo=True, source_root=root, strict_sources=True)
            self.assertEqual(outcome.errors, [], outcome.errors)
            html = render_html(self.template, data)
            self.assertEqual(validate_html(html, data, self.template).errors, [])
            self.assertEqual(len(extract_html_report(html)[0]['assessment']['findings']), 1)

    def test_auto_security_level_inference_from_completed_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'api').mkdir()
            (root / 'api' / 'Users.cs').write_text(
                '// [Authorize(Roles = "Ignored")]\n'
                '[Authorize(Roles = "Admin")]\n', encoding='utf-8'
            )
            data = self.fresh()
            data['assessment']['checks'][0]['execution'].update(
                state='completed', methods=['source review'],
                summary='Reviewed access controls in Users.cs',
                inspected_paths=['api/Users.cs']
            )
            assessment = infer_security_level(data['assessment'], root)
            self.assertEqual(assessment['status'], 'preliminary')
            self.assertEqual(assessment['level'], 'C')
            self.assertEqual(assessment['evidence'][0]['line_start'], 2)
            data['project']['security_level_assessment'] = assessment
            self.assertEqual(validate_data(data, allow_demo=True, source_root=root).errors, [])
            data['assessment']['checks'][0]['execution']['inspected_paths'] = []
            self.assertIn('inspected_paths', ' '.join(
                validate_data(data, allow_demo=True, source_root=root).errors))

    def test_auto_security_level_unknown_when_unreviewed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'api.cs').write_text('[Authorize(Roles = "Admin")]\n')
            assessment = infer_security_level(self.fresh()['assessment'], root)
            self.assertEqual(assessment['status'], 'undetermined')
            self.assertEqual(assessment['level'], '待確認')
            self.assertTrue(assessment['missing_information'])

    def test_security_level_display_and_basis(self):
        data = self.fresh()
        data['project']['security_level'] = 'C'
        data['project']['security_level_basis'] = '權責單位分級認定紀錄'
        self.assertEqual(validate_data(data, allow_demo=True).errors, [])
        page = render_html(self.template, data)
        self.assertIn('資通安全責任等級（A～E）', page)
        self.assertIn('資通安全責任等級分級辦法', page)
        self.assertIn("project.security_level+' 級（已提供正式分級）'", page)
        self.assertIn('project.security_level_basis', page)
        self.assertIn('安全等級判斷說明', page)
        self.assertEqual(validate_html(page, data, self.template).errors, [])

    def test_cli_generate_and_validate(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            project = root/'project.json'
            project.write_text(json.dumps(self.example['project'], ensure_ascii=False), encoding='utf-8')
            assess = root/'assessment.json'
            assess.write_text(json.dumps(self.example['assessment'], ensure_ascii=False), encoding='utf-8')
            html = root/'security.html'
            presentation = root/'presentation.json'
            presentation.write_text(json.dumps(self.example['presentation'], ensure_ascii=False), encoding='utf-8')
            generated = root/'report.json'
            cmd = [sys.executable, str(HERE/'scripts/generate_report.py'), '--assessment',str(assess),
                   '--project',str(project),'--presentation',str(presentation),'--allow-demo','--output',str(html),'--save-report',str(generated)]
            done = subprocess.run(cmd, text=True, capture_output=True)
            self.assertEqual(done.returncode, 0, done.stdout+done.stderr)
            report = json.loads(generated.read_text(encoding='utf-8'))
            self.assertEqual(report['web_guide_v32_appendix3']['header_count'], 6)
            self.assertEqual(report['web_guide_v32_appendix3']['status_counts'], {'not_assessed': 6})
            self.assertEqual(report['web_guide_v32_appendix3']['scope']['excluded_implementation_technologies'], ['Java', 'PHP'])
            self.assertIn('id="webHeadersContent"', html.read_text(encoding='utf-8'))
            self.assertEqual(report["web_guide_v32_appendix1"]["item_count"], 55)
            self.assertEqual(report["web_guide_v32_appendix1"]["category_count"], 27)
            self.assertIsNone(report["web_guide_v32_appendix1"]["applicable_items"])
            self.assertEqual(report["web_guide_v32_appendix1"]["status_counts"], {"pending_level": 55})
            self.assertIn('id="webAppendixContent"', html.read_text(encoding='utf-8'))
            self.assertEqual(report['web_guide_v32']['category_count'], 29)
            self.assertEqual(report['web_guide_v32']['implementation_topic_count'], 35)
            self.assertEqual(report['web_guide_v32']['scope']['excluded_implementation_technologies'], ['Java', 'PHP'])
            self.assertIn('id="webGuideContent"', html.read_text(encoding='utf-8'))
            self.assertTrue(any('WEB應用程式安全參考指引 V3.2' in s for s in report['presentation']['standards']))
            self.assertEqual(report['system_baseline']['total_controls'], 80)
            self.assertIsNone(report['system_baseline']['applicable_controls'])
            self.assertEqual(report['system_baseline']['status_counts'], {'pending_level': 80})
            self.assertIn('id="systemBaselineContent"', html.read_text(encoding='utf-8'))
            rule_map = {r['id']: r for r in report['rules']}
            self.assertIn('A01:2025', [x['id'] for x in rule_map['IN-08']['owasp_2025_categories']])
            self.assertNotIn('A10:2025', [x['id'] for x in rule_map['IN-08']['owasp_2025_categories']])
            self.assertIn('A03:2025', [x['id'] for x in rule_map['SI-01']['owasp_2025_categories']])
            self.assertIn('id="owasp2025Content"', html.read_text(encoding='utf-8'))
            self.assertTrue(any('OWASP Top 10:2025' in s for s in report['presentation']['standards']))
            result = subprocess.run([sys.executable, str(HERE/'scripts/validate_report.py'),
                                     '--html',str(html),'--report',str(generated),'--allow-demo'],
                                    capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)


if __name__ == '__main__':
    unittest.main()
