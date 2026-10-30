"""零 rule_reviews 檔案的跨檔制式篩選理由不可被當成可信逐檔分析。"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/lib"))
from file_review_integrity import repeated_screening_reason_errors


def row(path, reason, reviewed=False):
    return {
        "path": path,
        "rule_reviews": [{"rule_id": "AC-01"}] if reviewed else [],
        "category_screening": {
            "AC": {"rule_ids": [], "reason": reason},
        },
    }


class RepeatedScreeningReasonsTests(unittest.TestCase):
    def test_detects_large_cross_file_boilerplate_group(self):
        rows = [row(f"src/{i}.cs", "本檔未發現存取控制相關程式邏輯，故無直接適用項目。")
                for i in range(20)]
        errors = repeated_screening_reason_errors(rows)
        self.assertTrue(any("AC:" in x and "20/20" in x for x in errors))

    def test_file_specific_reasons_are_not_flagged(self):
        rows = [row(f"src/{i}.cs", f"此檔核對控制責任為 Job{i} 的獨立工作流程，無存取控制實作。")
                for i in range(20)]
        # 避免把純數字差異當成不同理由；改用語義不同的名稱。
        for index, entry in enumerate(rows):
            entry["category_screening"]["AC"]["reason"] = (
                f"來源包含獨立業務操作 {chr(65 + index)}，已追查其控制責任與權限入口。"
            )
        self.assertEqual(repeated_screening_reason_errors(rows), [])

    def test_non_empty_rule_reviews_not_in_zero_rule_sample(self):
        rows = [row(f"src/{i}.cs", "相同類別理由，已逐條實際檢查。", reviewed=True)
                for i in range(30)]
        self.assertEqual(repeated_screening_reason_errors(rows), [])


if __name__ == "__main__":
    unittest.main()
