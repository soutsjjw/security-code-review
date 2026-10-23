## 附件 3：HTTP 安全標頭防護設定（六項 CR-05 技術子檢核）

> 本文件由 [SKILL.md](../SKILL.md) 按需載入。統一的證據、狀態與不得憑空宣稱符合的限制，以主檔「共同證據與結果判定」為準；本頁保留此標準專屬要求。
> 文件內的 `standards/`、`scripts/`、`schemas/` 路徑皆相對 `SKILL_ROOT`，不是相對本 Markdown 所在目錄。

- 來源：《附件3 HTTP安全標頭防護設定.pdf》，共 10 頁。標準 `NICS-WEB-GUIDE-APPENDIX3`；清冊 `standards/nics-web-v3.2-appendix3.yaml`，依主文 `NICS-WEB-4.5.3.4` 對照六項：Content-Security-Policy、Strict-Transport-Security、X-Content-Type-Options、X-Frame-Options、Referrer-Policy、Permissions-Policy。
- **不增加正式規則數**，原 `CR-05` 是主要檢核，CSP 同時關聯 `IN-02`，HSTS 同時關聯 `CR-01`，**不得將 HTTP 標頭直接視為 `CR-06` Cookie 安全屬性**。佇列 `next_checks[].web_guide_v32_appendix3` 提示要實際查核的設定值、路徑、部署等細節；Finding 仍以原有規則記錄。
- **技術限制**：只採 ASP.NET/.NET、IIS、`web.config`、Middleware、反向代理及通用 HTTP 回應要求；排除 Java Servlet Filter、`web.xml` 與 PHP 專屬檢查。不得把原 PDF 第 9 頁含 `unsafe-inline`／`unsafe-eval` 的 CSP 程式碼當作安全建議；須確認 CSP 真正強制執行且不過寬、HSTS 子網域和 preload 風險、Permissions-Policy 正確語法與實際瀏覽器支援。
- 必須分開記錄 **靜態程式碼／設定檢查** 與 **實際 HTTPS HTTP 回應證據**，並核對部署環境、URL 或測試工件識別、日期、標頭有效值。未提供回應證據時只能記 `review` 或 `not_assessed`。可根據實際來源錯誤記 `fail`，但應註明部署影響待驗。
- `report.json.web_guide_v32_appendix3` 與 HTML 會獨立顯示六項結果；無真實證據預設六項皆 `not_assessed`，不受原 `CR-05` 的 Pass 影響。若有實際查證，Agent 可於受測專案 `reports/security-code-review/web_appendix3_assessment.json` 記錄 `{"checks":[{"id":"NICS-WEB-A3-CSP","status":"review","reason":"已檢查配置但待實測 HTTPS 回應","reviewer":"資安審查人員","verified_on":"2026-10-20","environment":"測試環境","observed_value":"default-src 'self'","evidence":["web.config:42"],"http_response_evidence":[]}]}`（格式示意）。pass 須非空 `http_response_evidence` 和 `environment`；fail 須有真實設定或回應證據；其他人工判定皆需理由、審核者與日期。
- 來源 PDF 第 7 頁提及 SecurityHeaders.com、Mozilla Observatory、Google CSP Evaluator，作為**經授權**的輔助驗證工具；工具評分或警示不能直接當法遵結論。附件3自身沒有正式「普／中／高」獨立矩陣，不得擅自判斷 N/A。
- 保留原有所有 Finding、70 項續跑流程、V3.2 主文與附件1。即使缺少外部部署證據，仍要完成其餘的程式碼審查；不修改受測專案原始碼。
