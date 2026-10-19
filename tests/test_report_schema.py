"""JSON Schema 契約測試；非原始碼審查器、非完整報告驗證器。"""
import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]


def load_json(path):
    return json.loads((ROOT / path).read_text('utf-8'))


class ReportSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = load_json('schemas/report.schema.json')
        cls.assessment_schema = load_json('schemas/assessment.schema.json')
        registry = Registry().with_resource(
            'assessment.schema.json', Resource.from_contents(cls.assessment_schema)
        )
        cls.validator = Draft202012Validator(
            cls.schema, registry=registry, format_checker=FormatChecker()
        )
        cls.example = load_json('examples/report-data.example.json')
        Draft202012Validator.check_schema(cls.schema)

    def errors(self, data):
        return [e.message for e in self.validator.iter_errors(data)]

    def test_valid_all_review_example(self):
        self.assertEqual(self.errors(self.example), [])
        self.assertEqual(len(self.example['assessment']['checks']), 70)
        self.assertEqual({x['status'] for x in self.example['assessment']['checks']}, {'review'})

    def test_execution_is_required(self):
        data = copy.deepcopy(self.example)
        data['assessment']['checks'][0].pop('execution')
        self.assertTrue(self.errors(data))

    def test_demo_pending_is_structurally_valid(self):
        self.assertEqual({c['execution']['state'] for c in self.example['assessment']['checks']}, {'pending'})
        self.assertEqual(self.errors(self.example), [])

    def test_missing_report_schema_version_rejected(self):
        data = copy.deepcopy(self.example)
        data.pop('report_schema_version')
        self.assertTrue(self.errors(data))

    def test_duplicate_rule_id_rejected(self):
        data = copy.deepcopy(self.example)
        data['rules'][-1] = copy.deepcopy(data['rules'][0])
        self.assertTrue(self.errors(data))

    def test_wrong_rule_category_rejected(self):
        data = copy.deepcopy(self.example)
        data['rules'][0]['category'] = 'AU'
        self.assertTrue(self.errors(data))

    def test_pass_without_evidence_rejected(self):
        data = copy.deepcopy(self.example)
        data['assessment']['checks'][0]['status'] = 'pass'
        self.assertTrue(self.errors(data))

    def test_fail_without_evidence_rejected(self):
        data = copy.deepcopy(self.example)
        data['assessment']['checks'][0]['status'] = 'fail'
        self.assertTrue(self.errors(data))

    def test_na_without_sufficient_reason_rejected(self):
        data = copy.deepcopy(self.example)
        data['assessment']['checks'][0].update(status='na', applicability_reason='無')
        self.assertTrue(self.errors(data))

    def test_invalid_security_level_rejected(self):
        data = copy.deepcopy(self.example)
        data['project']['security_level'] = '高'
        self.assertTrue(self.errors(data))

    def test_security_level_requires_basis(self):
        data = copy.deepcopy(self.example)
        data['project']['security_level'] = 'B'
        data['project'].pop('security_level_basis', None)
        self.assertTrue(self.errors(data))
        data['project']['security_level_basis'] = '主管機關核定文號與日期'
        self.assertEqual(self.errors(data), [])

    def test_security_level_unknown_and_na(self):
        for value in ('待確認', '不適用'):
            data = copy.deepcopy(self.example)
            data['project']['security_level'] = value
            data['project'].pop('security_level_basis', None)
            self.assertEqual(self.errors(data), [])

    def test_invalid_overall_risk_rejected(self):
        data = copy.deepcopy(self.example)
        data['presentation']['overall_risk']['level'] = 'severe'
        self.assertTrue(self.errors(data))

    def test_missing_location_line_rejected(self):
        data = copy.deepcopy(self.example)
        data['presentation']['finding_details']['F-01'] = {
            'locations': [{'path': 'src/example.cs', 'line_start': 4}]
        }
        self.assertTrue(self.errors(data))

    def test_unsafe_finding_id_rejected(self):
        data = copy.deepcopy(self.example)
        data['presentation']['finding_details']['F-01#x'] = {}
        self.assertTrue(self.errors(data))

    def test_invalid_priority_group_rejected(self):
        data = copy.deepcopy(self.example)
        data['presentation']['priorities'] = [{'label': '立即', 'finding_ids': []}]
        self.assertTrue(self.errors(data))

    def test_missing_project_name_rejected(self):
        data = copy.deepcopy(self.example)
        data['project']['name'] = '   '
        self.assertTrue(self.errors(data))

    def test_valid_demo_finding_shape(self):
        data = copy.deepcopy(self.example)
        data['assessment']['findings'] = [{
            'id': 'F-01', 'title': '僅格式測試', 'severity': 'low', 'check_ids': ['AC-01'],
            'impact': '純格式測試，非實際弱點',
            'evidence': [{
                'kind': 'other', 'description': '僅為資料格式測試的虛構內容',
                'collected_on': '2026-10-18', 'source_version': 'DEMO'
            }],
            'remediation': '僅供 JSON Schema 契約測試'
        }]
        data['presentation']['finding_details']['F-01'] = {
            'description': '虛構情境，僅供測試',
            'risk': '虛構風險，僅供測試',
            'locations': [{'path': 'src/example.cs', 'line_start': 1, 'line_end': 2}],
            'before_code': '// demo only', 'after_code': '// demo only'
        }
        data['presentation']['priorities'] = [
            {'label': '示範排序', 'finding_ids': ['F-01'], 'description': '僅測試引用格式'}
        ]
        self.assertEqual(self.errors(data), [])


if __name__ == '__main__':
    unittest.main()
