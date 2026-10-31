## 《資通系統防護基準驗證實務》V1.3 第二層驗證

> 本文件由 [SKILL.md](../SKILL.md) 按需載入。統一的證據、狀態與不得憑空宣稱符合的限制，以主檔「共同證據與結果判定」為準；本頁保留此標準專屬要求。
> 文件內的 `standards/`、`scripts/`、`schemas/` 路徑皆相對 `SKILL_ROOT`，不是相對本 Markdown 所在目錄。

- 國家資通安全研究院 115/06/03 V1.3 之第 2 章包含七構面、27 類、**80 項控制措施**。以 `standards/tw-system-baseline-v1.3.yaml` 為第二層版本化清冊，保存原文 2.x 條次、PDF 頁碼、適用「普／中／高」、查核型態（source/hybrid/external）、證據方向與原 70 項相關規則。
- **不得修改或重新編號原 70 項，也不得將 80 項加總成 150 個 Code Review 規則**。佇列 `next_checks[].system_baseline_v13_controls` 是源碼檢查參照；對 source/hybrid 可閱讀程式碼與設定，external 需政策、正式工具掃描、滲透測試、部署、演練或營運紀錄。將已檢查方向及待補證據註記於相關 70 項的審查摘要，不得謊稱已完成獨立驗證。
- 系統防護需求等級「普／中／高」（附表九／十）**與**機關責任等級「A～E」不同。依 `project.protection_demand_level` 及 `protection_demand_level_basis` 取得正式依據決定適用數（普 45、中 62、高 80）；若證據不足則不填值或設為「待確認」，不可因看見特定程式碼而推定正式級別。`project.protection_demand_level_assessment` 的初步研判只顯示在報告基本資訊，不改變 80 項適用性。
- `report.json.system_baseline` 與 HTML 的獨立章節記錄各項狀態。不提供另外的真實驗證資料時，自動標示 `pending_level`／`not_assessed`／`not_applicable_by_level`。
- 在受測專案的 `reports/security-code-review/baseline_assessment.json` 可記錄經實際核對的獨立項目：`{ "controls": [{ "id": "TW-SB-2.1.3.2", "status": "review", "reason": "已檢查原始碼，尚待實機授權測試", "reviewer": "審核人員", "verified_on": "2026-10-20", "evidence": [] }] }`。需完整理由、日期和審核者，`pass/fail` 更須有具體獨立佐證路徑或外部工件編號。
- 只對確實完成的項目寫入人工決定，不要把人工基準結果寫進原有 `assessment.json.checks`。如果舊版報告已有 Finding 或已審查結果，一律保留；補充基準不須清空原紀錄。
- PDF 的附件一僅見起始頁，未取得完整附件，故對照以第 2 章 80 項內容為準；不是聲稱已比對完整附表影本。
- `complete_review.py` 仍在受測專案執行，沿用 `$security-code-review`。只有 70/70 審查完成才產生報告；獨立防護基準項目可保留待確認，不影響既有交付條件，但不可對外宣稱整體符合性驗證完成。
