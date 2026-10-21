"""僅供回歸測試使用的逐檔審查資料工廠，不可用於實際受測專案。"""
import hashlib

CATEGORIES = ("AC", "AU", "IN", "CR", "EH", "LG", "DP", "PD", "BC", "SI")


def make_file_review(root, path, rule_ids=()):
    rule_ids = list(rule_ids)
    screening = {}
    for category in CATEGORIES:
        ids = [rid for rid in rule_ids if rid.startswith(category + "-")]
        screening[category] = {
            "rule_ids": ids,
            "reason": (f"測試資料：已核對 {category} 類檢查項目，確認此檔案中"
                       + ("存在需檢查的相關控制實作與對應行號。" if ids else "沒有此類別的直接控制實作。"))
        }
    return {
        "path": path,
        "sha256": hashlib.sha256((root / path).read_bytes()).hexdigest(),
        "summary": "測試用的完整逐檔檢查記錄，已確認來源、類別適用性與來源行號。",
        "methods": ["read_source"],
        "category_screening": screening,
        "rule_reviews": [{
            "rule_id": rid, "result": "review",
            "reason": f"測試用的 {rid} 來源核對與適用性判定，仍需其他相關安全佐證。",
            "line_start": 1, "line_end": 1,
        } for rid in rule_ids],
    }
