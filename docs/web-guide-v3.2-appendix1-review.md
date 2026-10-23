## 附件 1：Web 應用程式安全查檢表（V3.2 主文件附錄）

> 本文件由 [SKILL.md](../SKILL.md) 按需載入。統一的證據、狀態與不得憑空宣稱符合的限制，以主檔「共同證據與結果判定」為準；本頁保留此標準專屬要求。
> 文件內的 `standards/`、`scripts/`、`schemas/` 路徑皆相對 `SKILL_ROOT`，不是相對本 Markdown 所在目錄。

- 來源：`附件1 Web應用程式安全查檢表.pdf`（完整 5 頁）。7 大構面、27 類共 **55 項**；依原文 ◎ 統計普33、中44、高55。版本化清冊：`standards/nics-web-v3.2-appendix1.yaml`，ID `NICS-WEB-A1-001` 至 `055`。原附件的「是否符合」欄空白，不能假設全數通過。
- `review_queue.py` 每批 `next_checks[].web_guide_v32_appendix1` 提供相關附件細項；在原有 70 項實際審查時按適用情境、原始碼路徑與行號、依賴及設定真實證據檢查，需政策、運作、正式掃描或滲透測試證據者標示待確認；不新增重複 Finding。
- 附件的普／中／高採用 `project.protection_demand_level` 和 `project.protection_demand_level_basis`，與 A～E 機關責任等級完全分開。尚無系統分級則 55 項為 `pending_level`，有分級而未驗證的適用項為 `not_assessed`，非適用級別為 `not_applicable_by_level`。
- 當有真實可核對證據，可在受測目錄 `reports/security-code-review/web_appendix1_assessment.json` 寫入 `{"checks":[{"id":"NICS-WEB-A1-001","status":"review","reason":"已查驗程式碼，實際逾時效果尚待佐證","reviewer":"資安審查人員","verified_on":"2026-10-20","evidence":[]}]}`。這是**格式示範**；所有人工記錄均需理由、審核者及日期，不能聲稱自動 SAST、實際防火牆設定或滲透測試已完成。既有 `assessment.json` 與 Findings 不得刪除。
- `generate_report.py` 自動載入上述選填檔案；`report.json.web_guide_v32_appendix1` 與 HTML 新增逐項對照／狀態／證據章節。重跑舊報告不能推定此前已完成新的 55 項，必須先覆核證據。
- 維持技術限定：**ASP.NET/.NET 與不分語言的 Web 安全要求，排除 Java／PHP 專屬實作**。附件只列 27 類，未列 V3.2 主文 `4.4.5`、`4.7.1` 及 `4.5.3.4` HTTP 安全標頭細節；主文仍需完整檢測。
- 附件的「12 字元與字元類型、定期輪替、CAPTCHA、Regex」是來源明列的實作要求，不可在未確認機關政策、風險與等效防護前無條件判定安全或法遵違規。
