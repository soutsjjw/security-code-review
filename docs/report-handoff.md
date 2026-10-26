# 正式完整審查的報告與交付

僅適用未指定 `--categories` 的完整模式；開始正式驗證與產出 HTML／JSON 前必讀本文件。分類報告使用 [分類審查操作契約](category-review.md)，不可共用正式 `ready_for_report`。

## 品質回歸驗收（新版本發佈前執行）

對固定 16 個隔離案例實際執行完整 Skill 審查、保留來源與執行證據後，才可呼叫 `quality_acceptance.py --workspace "<CASE_WORKSPACE>" --output "<QUALITY_RESULT>.json"`，並以 `--compare "<PREVIOUS_QUALITY_RESULT>.json"` 檢查跨版本漏報、誤報、待確認、跨檔追查及來源證據是否退步。**工具本身不替代理執行 16 次審查，也不能用合成預測冒充模型品質。** 未執行完整案例審查時，應明確標示品質實測未完成；不能把單元測試通過寫成已達到實測品質門檻。完整操作見 [品質驗收指引](quality-acceptance.md)。

## 全規則品質契約與真實審查驗收

發布前先執行 `sh "<SKILL_ROOT>/scripts/run-python.sh" "<SKILL_ROOT>/scripts/quality_gate.py" --matrix-only`，逐條驗證 70 項適用性、Pass／Fail／Review 判定契約及具體反向情境。對已完成的受測專案，執行 `sh "<SKILL_ROOT>/scripts/run-python.sh" "<SKILL_ROOT>/scripts/quality_gate.py" --target "<TARGET_ROOT>" --output "<QUALITY_RESULT>.json"`，確認判定、跨檔、控制有效性與反向複核品質守門、100% 來源覆蓋、70/70、第二輪 70/70、正式 HTML／JSON 結果與來源快照一致。另用固定 16 案例真正完成全規則審查，交由 `quality_acceptance.py` 驗收；可依同一受測來源與題庫比較前後版本。這兩個工具都**不代替主代理實際審查，也不能把模擬測試標示為真實模型驗收**。缺少 Agent 真實工件時只能標示未完成品質驗收。操作說明見 [真實審查品質驗收](quality-acceptance.md)。

4. 在 **受測專案**（非 Skill）建立 `reports/security-code-review/`，並寫入：
   - `assessment.json`：符合 `schemas/assessment.schema.json` 的 70 項檢核、已驗證 Finding、真實 Git Revision 與證據。
   - `project.json`：本系統的顯示資料，至少 `name` 與 `language_framework`（`--init` 會從 `.csproj` 預填；仍為佔位值時 `complete_review.py` 會拒絕交付）。Agent **須在 70 項程式碼審查時同步嘗試法定 A～E 級的初步研判**，不先要求使用者填級別，亦不因缺少資訊中斷審查。依《資通安全責任等級分級辦法》第 4～10 條查證已實際讀取的程式碼、權限區分、設定、設計及業務文件與服務覆蓋範圍；證據充足時寫入 `project.security_level_assessment`，包含 `status:"preliminary"`、`level:"A～E之一"`、`basis`（規定條次及具體理由）、`evidence:[{path,line_start,line_end}]`（須已列入 completed 的 inspected_paths）及 `missing_information`。不可僅憑登入功能、漏洞數推定 A／B 級；C 級權限管理只是第 6 條**技術條件線索**，尚需確認機關維運事實及更高級別是否適用；未找到權限程式碼不能推斷 D／E 級。
   - 若證據不足，Agent 應記錄 `security_level_assessment: {status:"undetermined",level:"待確認",basis:"無法判定原因",evidence:[],missing_information:["待核對機關業務及核定資料"]}`，報告顯示說明，**不詢問使用者且繼續其餘 70 項審查**。若未填初判，報告產生器自動檢視 completed 規則的 inspected_paths，以具體角色／權限管理程式碼提出 C 級技術線索，否則自動記錄「待確認」原因。
   - `security_level`（A～E）只用於已提供的**正式**認定／核定資料，並需 `security_level_basis`；AI 初判不得寫入此欄。正式分級優先顯示，與程式碼整體風險、資通系統防護需求分級分開。
   - `presentation.json`（選用）：真實審查方法／限制、改善優先序及 Before / After。不可補造程式碼、風險或安全優點。
5. **只有 70 項均有真實證據且已完成、來源覆蓋率達 100%、兩類完整性錯誤均為空，且 `review_queue.py` 回傳 `ready_for_report=true`，才能開始報告階段。** 從 `TARGET_ROOT` 作為工作目錄，由 Agent 自動呼叫：

   ```bash
   sh "<SKILL_ROOT>/scripts/run-python.sh" "<SKILL_ROOT>/scripts/complete_review.py" --target "<TARGET_ROOT>"
   ```
   Windows（PowerShell）：
   ```powershell
   & "<SKILL_ROOT>\scripts\run-python.cmd" "<SKILL_ROOT>\scripts\complete_review.py" --target "<TARGET_ROOT>"
   ```
   程式從 `SKILL_ROOT` 載入規則、Schema 和 HTML 模板，將所有報告寫在 `TARGET_ROOT/reports/security-code-review/`，並串接原有檢核 JSON、HTML 生成及最終驗證。
6. 若找不到 Python 3.10+ 或 `requirements.txt` 相依套件不符，**立即停止 Python 腳本階段並保留既有進度**，回報偵測結果與所需安裝方式。找到可用 Python 但缺套件時，啟動器會顯示該直譯器的 `-m pip install -r "<SKILL_ROOT>/requirements.txt"` 指令；若完全沒有 Python，須先在 Agent 實際執行環境安裝 Python 3.10+。**不得自行安裝、變更全域環境、清空既有紀錄或假稱 HTML 已產生**；取得使用者同意後才可在隔離環境安裝並重新執行。
7. 逐項確認 `completed` 數量為 70、`source_coverage.missing_source_file_count` 為 0 才執行報告程序。若仍有 `pending`／`blocked`，必須主動執行佇列迴圈查核其餘項目；**只有真正無法繼續的執行阻礙才回報中斷**，並列出已保存的進度與確切錯誤，不得因一般審查工作尚多就結束。**不要以 3 個優先弱點或部分分析代替最終 HTML／JSON**。只有三階段程式都返回 0，才能回報 HTML／JSON 已驗證；列出實際路徑、弱點數與未能驗證的範圍。原始碼取證須填相對 `TARGET_ROOT` 的檔案與真實行號，避免輸出 Token、密碼與個資。

## 基本資訊與摘要的自動判定

- **審查範圍**：必須盤點實際專案（例如各 `.csproj`、實際專案根目錄），將真實名稱與相對路徑寫入 `assessment.scope_details.projects`；每條 completed 檢核僅登錄實際讀取的 `execution.inspected_paths`。報告僅以去重後的已審查檔案數、專案數及副檔名類型產生摘要；若無可靠專案對照，顯示「專案數待確認」，不可把根目錄臆測成一個專案。
- **規則版本**：報告顯示當前 `rules.json` 的正式規則集版本（目前 `2.0.0`）。舊版 `assessment.ruleset_version` 原值不得偽造或覆寫；若為 `2.0.0-rc1`，明確另註為歷史紀錄並依實際證據補查新增規範。
- **審查工具**：Agent 若有可辨識的實際執行介面證據，須將 `Codex App`、`Codex CLI` 或 `Claude Code` 寫入 `presentation.reviewer`；亦可由使用者設定環境變數 `SECURITY_CODE_REVIEW_EXECUTOR` 為上述其中一個值。若只能辨識 Codex 而無法區分 App／CLI，應顯示 `Codex（執行介面無法辨識）`；不得猜測或為了完成審查要求使用者填寫。請勿將 `security-code-review-agent` 當作實際介面名稱。
- **個資處理**：優先使用 `project.json` 中已有可核對的「是／否」聲明；缺少該聲明時，報告產生器以 completed 的逐檔審查檔案尋找明確個資處理欄位線索，產生「是（靜態初判）」的佐證或「待確認」原因。**未發現個資欄位不代表不處理個資，不得自動判定「否」**；原始佐證應只有路徑與行號，勿複製真實個資。
- **初步研判佐證**：不在基本資訊重複列出完整路徑與行號；安全等級與個資初判的來源仍保留於 JSON。
- **尚待確認資訊**：自動彙整法定分級、個資待確認、規則 `review` 與未取得的部署／政策／動態驗證證據，去重呈現，不得因缺乏外部佐證中斷 70 項審查。
- **整體風險**：由已記錄 Finding 的嚴重度、影響、證據信心與仍未驗證的利用條件自動產生靜態初判；不能按 Finding 數量簡單加總，亦不能因無 Finding 就判定低風險。未經證明的外部暴露、補償控制及業務衝擊，必須註明待驗證；不需使用者先核定才輸出初判，也不能當成正式風險接受。

## 報告輸出位置

下方為**完整模式**正式報告路徑；分類模式獨立輸出於 `partial/<分類>/`，詳見 [分類審查操作契約](category-review.md)。

```text
<TARGET_ROOT>/
└── reports/security-code-review/
    ├── assessment.json
    ├── project.json
    ├── presentation.json      # 選填
    ├── report.json
    └── CodeReview_YYYYMMDD.html
```

## 執行與交付準則

以下為完整模式的交付準則；分類模式以 [分類審查操作契約](category-review.md) 的各分類驗證與獨立報告為準。

- 除非確有阻斷錯誤，**禁止回覆「70 項都是 pending／只有三項發現／請下次續跑」並直接結束**；那只是尚未開始佇列迴圈。必須立即啟動查核直到 `ready_for_report=true`。

- 使用者只下達一次 `$security-code-review`；Agent 應自行分析、持續審查與產生報告，不因風險發現或唯讀編碼回退詢問「是否繼續／是否先修復／是否允許解碼」。
- 分批完成 70 項時，持續更新暫存審查資料。只有實際檢核完成才能把 `execution.state` 由 `pending` 改成 `completed`。
- Finding 的 `remediation` 只代表建議，**不得以執行本 Skill 為由修改受測程式碼**；若未能確認可利用性，清楚寫明靜態檢核與部署／動態測試限制。
- 最終報告包含所有已發現 Finding；嚴重弱點可列於改善優先序，但不能排擠其他 70 項檢核。

## 禁止事項

- 不將受測專案的 JSON 或 HTML 寫入 Skill 安裝目錄。
- 不複製其他系統的審查結果或使用示範檔作為正式證據。
- 不將 OWASP Top 10 風險類別宣稱為直接合規條文；經核准的風險例外不會自動讓 Fail 變 Pass。
- 不以 Schema／HTML 驗證通過來宣稱漏洞已完成動態測試或政策簽核。
