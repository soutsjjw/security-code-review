"""V1.3 資通系統防護基準與原 70 項分層模型測試。"""
import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

from system_baseline import (load_catalog, build_system_baseline,
                             validate_system_baseline, source_review_hints,
                             review_from_report)


class SystemBaselineTests(unittest.TestCase):
    def test_catalog_80_ids_levels_and_domains(self):
        catalog = load_catalog()
        self.assertEqual(len(catalog), 80)
        self.assertEqual(len({item['id'] for item in catalog}), 80)
        self.assertEqual(
            {level: sum(level in item['applicable_levels'] for item in catalog)
             for level in ('普', '中', '高')},
            {'普': 45, '中': 62, '高': 80})
        self.assertEqual(
            {item['domain'] for item in catalog},
            {'存取控制', '事件日誌與可歸責性', '營運持續計畫',
             '識別與鑑別', '系統與服務獲得', '系統與通訊保護', '系統與資訊完整性'})
        self.assertEqual(next(x for x in catalog if x['source_section'] == '2.5.3.4')['applicable_levels'], ['高'])

    def test_all_pending_when_no_official_system_level(self):
        report = build_system_baseline({'name': '測試系統'})
        self.assertEqual(report['demand_level'], '待確認')
        self.assertIsNone(report['applicable_controls'])
        self.assertEqual(report['status_counts'], {'pending_level': 80})
        self.assertEqual(validate_system_baseline({'name': '測試系統'}, report), [])

    def test_level_is_independent_of_agency_A_to_E(self):
        project = {'security_level': 'A', 'name': '示例'}
        report = build_system_baseline(project)
        self.assertEqual(report['demand_level'], '待確認')
        with self.assertRaises(ValueError):
            build_system_baseline({'protection_demand_level': '中'})
        with self.assertRaises(ValueError):
            build_system_baseline({'protection_demand_level': 'A',
                                   'protection_demand_level_basis': '錯誤'})
        for level, expected in [('普', 45), ('中', 62), ('高', 80)]:
            project = {'protection_demand_level': level, 'protection_demand_level_basis': '已核對分級資料'}
            report = build_system_baseline(project)
            self.assertEqual(report['applicable_controls'], expected)
            self.assertEqual(report['status_counts'].get('not_assessed'), expected)
            self.assertEqual(report['status_counts'].get('not_applicable_by_level', 0), 80 - expected)

    def test_evidence_gated_independent_verification(self):
        project = {'protection_demand_level': '普', 'protection_demand_level_basis': '核定紀錄'}
        verified = {'id': 'TW-SB-2.1.3.2', 'status': 'pass',
                    'reason': '檢閱伺服器授權與實際測試紀錄',
                    'reviewer': '資安審核者', 'verified_on': '2026-10-20',
                    'evidence': ['ART-01/授權測試紀錄']}
        report = build_system_baseline(project, {'controls': [verified]})
        record = next(x for x in report['controls'] if x['id'] == verified['id'])
        self.assertEqual(record['status'], 'pass')
        self.assertEqual(report['status_counts']['pass'], 1)
        self.assertEqual(report['status_counts']['not_assessed'], 44)
        self.assertEqual(validate_system_baseline(project, report), [])
        missing = copy.deepcopy(verified)
        missing['evidence'] = []
        with self.assertRaises(ValueError):
            build_system_baseline(project, {'controls': [missing]})
        wrong = copy.deepcopy(verified)
        wrong['id'] = 'TW-SB-2.5.3.4'  # 只適用高級
        with self.assertRaises(ValueError):
            build_system_baseline(project, {'controls': [wrong]})
        with self.assertRaises(ValueError):
            build_system_baseline({'name': '未知分級'}, {'controls': [verified]})

    def test_review_is_not_pass(self):
        project = {'protection_demand_level': '中', 'protection_demand_level_basis': '核定紀錄'}
        review = {'controls': [{'id': 'TW-SB-2.2.1.1', 'status': 'review',
                              'reason': '已看日誌程式碼，但未取得六個月保存紀錄',
                              'reviewer': '資安審核者', 'verified_on': '2026-10-20',
                              'evidence': []}]}
        report = build_system_baseline(project, review)
        self.assertEqual(report['status_counts'].get('pass', 0), 0)
        self.assertEqual(report['status_counts']['review'], 1)
        self.assertEqual(review_from_report(report), review)
        self.assertEqual(validate_system_baseline(project, report), [])

    def test_tampering_rejected(self):
        project = {'protection_demand_level': '高', 'protection_demand_level_basis': '核定紀錄'}
        report = build_system_baseline(project)
        report['status_counts']['pass'] = 80
        self.assertTrue(validate_system_baseline(project, report))
        report2 = build_system_baseline(project)
        report2['controls'][0]['status'] = 'pass'
        self.assertTrue(validate_system_baseline(project, report2))

    def test_known_mappings_and_no_auto_compliance(self):
        rules = json.loads((ROOT / 'rules.json').read_text(encoding='utf-8'))['rules']
        mapped = source_review_hints(rules)
        self.assertEqual(set(mapped), {r['id'] for r in rules})
        ids = {entry['id'] for group in mapped.values() for entry in group}
        self.assertEqual(len(ids), 80)
        self.assertIn('TW-SB-2.1.3.2', [r['id'] for r in mapped['AC-08']])
        self.assertIn('TW-SB-2.5.3.4', [r['id'] for r in mapped['SI-01']])
        self.assertTrue(all('status' not in entry for group in mapped.values() for entry in group))


if __name__ == '__main__':
    unittest.main()
