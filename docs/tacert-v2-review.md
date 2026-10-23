## TACERT「網站安全管理指南」V2 補充檢核

> 本文件由 [SKILL.md](../SKILL.md) 按需載入。統一的證據、狀態與不得憑空宣稱符合的限制，以主檔「共同證據與結果判定」為準；本頁保留此標準專屬要求。
> 文件內的 `standards/`、`scripts/`、`schemas/` 路徑皆相對 `SKILL_ROOT`，不是相對本 Markdown 所在目錄。

- 文件：臺灣學術網路危機處理中心，《網站安全管理指南》，2022 年 8 月修訂 V2（PDF 11 頁）。檢核對照：`standards/tacert-v2-checklist.yaml`。
- 現有 70 項規則維持不變；另外以 **12 項常見缺失＋14 項網站安全檢測＋13 類防護措施（共 39 個補充檢核焦點）** 加強查核。這 39 個焦點不代表另外執行 39 個獨立規則，也不得把 70 項進度虛增。
- `review_queue.py` 的 `next_checks[].tacert_v2_checks` 會列出對應 TACERT 焦點、PDF 頁碼、檢查方向及證據要求。Agent 應對各項適用焦點實際查核，將結論、未取得之證據及 TACERT 項目 ID 寫入**原有規則的** `decision_reason`／`execution.summary`；證據仍依既有 Schema 存入 `evidence`。
- 可從原始碼與版控組態核對的項目採靜態查核；防火牆、RDP、Port 掃描、Windows 事件、登錄檔、惡意軟體防護、DDoS、備份還原、滲透測試等需部署/營運/動態佐證。缺少外部佐證時，記錄已做的靜態分析與待確認範圍後繼續其他項目。
- 相同風險僅記錄一個 Finding，可關聯多條規則；`related_rule_ids` 只是補充對照，**不是完整規範等價映射**。如 TACERT 建議「管理員定期變更密碼」，須先核對目前適用政策與等效控制，不直接以缺少輪替機制宣稱違反法律。
- 本版第二章 OWASP Top 10 列的是 **2021** 風險分類，不能直接引用為 **OWASP Top 10 2025**。二者於 `standards/standards-register.yaml` 分列。
