## WEB 應用程式安全參考指引 V3.2（限定 ASP.NET/.NET 與通用 Web 安全）

> 本文件由 [SKILL.md](../SKILL.md) 按需載入。統一的證據、狀態與不得憑空宣稱符合的限制，以主檔「共同證據與結果判定」為準；本頁保留此標準專屬要求。
> 文件內的 `standards/`、`scripts/`、`schemas/` 路徑皆相對 `SKILL_ROOT`，不是相對本 Markdown 所在目錄。

- 來源：《WEB應用程式安全參考指引》V3.2（114/12/31），第 4 章七構面、29 類控制、35 個明確細部技術條次；以 `standards/nics-web-guide-v3.2.yaml` 記錄章節、PDF 頁碼、審查方向與相關原 70 項規則。**這是技術參考，不是獨立 29/35 條新增完成規則、不是法定符合性結果**。
- **使用者排除 Java、PHP 實作技術**：不得使用此 V3.2 指引中的 Java/Servlet/JSP 或 PHP 語法、設定範例、函式庫或專屬檢測命令來設計檢核；僅採用 ASP.NET/.NET 的實作建議以及與語言無關的 Web 安全要求。這不代表遇到其他語言時跳過既有 70 項通用安全檢查。
- 對佇列 `next_checks[].web_guide_v32_checks` 的適用項目，實際核查程式碼路徑／行號及設定；V3.2 的細部條次含 `observed_levels` 與原 PDF 表格依據，只表示該節實作建議表至少一項涉及的普／中／高等級（同節多項可能適用不同等級），不得直接推定整個控制適用或自動 N/A；在 `decision_reason`／`execution.summary` 記錄相應 `NICS-WEB-4.x.x[.x]` ID、證據、不能確認的外部事項，並保持既有 Finding 與 70/70 計數。
- V3.2 新增 `4.5.3.4 HTTP 安全標頭`：需對照 `CR-05` 審查 CSP、HSTS、nosniff、X-Frame-Options、Referrer-Policy、Permissions-Policy 的實際設定與有效性；**文件部分 CSP 範例含 unsafe-inline / unsafe-eval，不能照抄或以有設定標頭即宣稱安全**。HSTS 與實際回應標頭可能仍需部署佐證。
- 指引第 3 章使用 OWASP Top 10:2021，保留歷史版本；既有 OWASP Top 10:2025 仍為獨立新版本分類。
- 主文件 PDF 共 253 頁，末頁僅列附件 1～3 標題；**附件 1 的完整五頁 PDF 已另行提供並建立 55 項清冊**，附件 2 尚未取得；附件 3 的 10 頁 PDF 已取得並建立六項安全標頭對照。
- `report.json.web_guide_v32` 與離線 HTML 的「WEB 應用程式安全參考指引 V3.2 技術對照」只呈現來源、技術範圍、控制映射及查核焦點；原始碼檢核結果與 V1.3 防護基準獨立呈現，不依映射自動推論合規。
