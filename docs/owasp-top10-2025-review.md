## OWASP Top 10:2025 十類風險對照

> 本文件由 [SKILL.md](../SKILL.md) 按需載入。統一的證據、狀態與不得憑空宣稱符合的限制，以主檔「共同證據與結果判定」為準；本頁保留此標準專屬要求。
> 文件內的 `standards/`、`scripts/`、`schemas/` 路徑皆相對 `SKILL_ROOT`，不是相對本 Markdown 所在目錄。

- 官方規範：https://top10.owasp.org/2025/，對照：`standards/owasp-top10-2025.yaml`（A01～A10，含審查方向、相關原規則、未完整涵蓋事項）；不修改 TACERT V2 對 2021 的歷史引用。
- 對 `review_queue.py` 各筆 `next_checks[].owasp_2025_categories`，按專案適用性實際檢查 `review_steps`。需於已查核規則的 `decision_reason`／`execution.summary` 指明相關 OWASP 2025 ID、取得的真實證據和仍待確認的 `coverage_gap`；不因缺少動態或外部證據中止其他審查。
- **新重點**：A03 供應鏈（傳遞相依、SBOM、受信任來源、CI/CD、工件簽章與發佈控制）；A09 記錄外還需驗證告警與應變；A10 錯誤／逾時／交易失敗與 fail-closed；SSRF 對應 A01:2025。
- 一個既有規則可能涉及多個 OWASP 類別，但不因此重複計數 Finding；`OWASP Top 10:2025` 是風險分類，不是獨立符合性判定。制度、平台或動態項目待佐證時保留 `review` 與說明。
- 從舊版續用的 `assessment.json` 若先前已完成，**不可僅因對照新增而宣稱 2025 已實際審查**；須核對舊證據是否涵蓋新重點，對缺漏部分重新分析並留下真實查核紀錄。 `report.json` 和 HTML 會呈現版本化風險對照及覆蓋限制。
