---
name: security-code-review
version: 2.1.7-rc1
description: 對目前專案或指定目錄執行公司共用的 70 項原始碼資安審查，驗證證據並自動產生通用離線 HTML 與 JSON 報告。
argument-hint: "[專案路徑或檢核範圍]"
---

# Security Code Review

> 本規則集仍為公司核定前的候選版，不可宣稱已獲法規或公司資安認證。

## 一句話使用

- Codex：`$security-code-review` 或 `$security-code-review <專案路徑或範圍>`
- Claude Code：`/security-code-review` 或 `/security-code-review <專案路徑或範圍>`
- 使用者**不需要**自行執行 Python 指令；Agent 負責呼叫必要的工具。

## 解析受測目標（優先處理）

1. **不提供參數**：從目前工作目錄找到所在 Git 專案的根目錄；若不是 Git 專案，就以目前目錄為根目錄。
2. **提供另一個現有專案目錄**：以該目錄為受測根目錄；不得因 Skill 安裝位置不同而改成掃描 Skill。
3. **提供本專案內的子目錄、檔案或文字需求**：保持目前專案根目錄為 `TARGET_ROOT`，將參數解讀為檢核範圍／重點；仍須輸出 70 個檢核 ID，未審查的範圍標明限制及 Review，不可假裝全案已掃描。
4. 未明確指定路徑時，**永遠不要把 `SKILL_ROOT` 當作受測目錄**。
5. 設 `SKILL_ROOT` 為目前 `SKILL.md` 的實際所在目錄（或其絕對路徑）；從此載入 `rules/`、`schemas/`、`scripts/`、`templates/`。

## TACERT「網站安全管理指南」V2 補充檢核

- 文件：臺灣學術網路危機處理中心，《網站安全管理指南》，2022 年 8 月修訂 V2（PDF 11 頁）。檢核對照：`standards/tacert-v2-checklist.yaml`。
- 現有 70 項規則維持不變；另外以 **12 項常見缺失＋14 項網站安全檢測＋13 類防護措施（共 39 個補充檢核焦點）** 加強查核。這 39 個焦點不代表另外執行 39 個獨立規則，也不得把 70 項進度虛增。
- `review_queue.py` 的 `next_checks[].tacert_v2_checks` 會列出對應 TACERT 焦點、PDF 頁碼、檢查方向及證據要求。Agent 應對各項適用焦點實際查核，將結論、未取得之證據及 TACERT 項目 ID 寫入**原有規則的** `decision_reason`／`execution.summary`；證據仍依既有 Schema 存入 `evidence`。
- 可從原始碼與版控組態核對的項目採靜態查核；防火牆、RDP、Port 掃描、Windows 事件、登錄檔、惡意軟體防護、DDoS、備份還原、滲透測試等需部署/營運/動態佐證。缺少證據時 **不得假稱 Pass，也不得假稱實際掃描**，記錄已做的靜態分析與待確認範圍後繼續其他項目。
- 相同風險僅記錄一個 Finding，可關聯多條規則；`related_rule_ids` 只是補充對照，**不是完整規範等價映射**。如 TACERT 建議「管理員定期變更密碼」，須先核對目前適用政策與等效控制，不直接以缺少輪替機制宣稱違反法律。
- 本版第二章 OWASP Top 10 列的是 **2021** 風險分類，不能直接引用為 **OWASP Top 10 2025**。二者於 `standards/standards-register.yaml` 分列。

## OWASP Top 10:2025 十類風險對照

- 官方規範：https://top10.owasp.org/2025/，對照：`standards/owasp-top10-2025.yaml`（A01～A10，含審查方向、相關原規則、未完整涵蓋事項）；不修改 TACERT V2 對 2021 的歷史引用。
- 對 `review_queue.py` 各筆 `next_checks[].owasp_2025_categories`，按專案適用性實際檢查 `review_steps`。需於已查核規則的 `decision_reason`／`execution.summary` 指明相關 OWASP 2025 ID、取得的真實證據和仍待確認的 `coverage_gap`；不因缺少動態或外部證據中止其他審查。
- **新重點**：A03 供應鏈（傳遞相依、SBOM、受信任來源、CI/CD、工件簽章與發佈控制）；A09 記錄外還需驗證告警與應變；A10 錯誤／逾時／交易失敗與 fail-closed；SSRF 對應 A01:2025。
- 一個既有規則可能涉及多個 OWASP 類別，但不因此重複計數 Finding；`OWASP Top 10:2025` 是風險分類，**不將類別對照或關聯規則 Pass 直接視為該類別完全符合**。制度、平台或動態項目待佐證時保留 `review` 與說明。
- 從舊版續用的 `assessment.json` 若先前已完成，**不可僅因對照新增而宣稱 2025 已實際審查**；須核對舊證據是否涵蓋新重點，對缺漏部分重新分析並留下真實查核紀錄。 `report.json` 和 HTML 會呈現版本化風險對照及覆蓋限制。

## 《資通系統防護基準驗證實務》V1.3 第二層驗證

- 國家資通安全研究院 115/06/03 V1.3 之第 2 章包含七構面、27 類、**80 項控制措施**。以 `standards/tw-system-baseline-v1.3.yaml` 為第二層版本化清冊，保存原文 2.x 條次、PDF 頁碼、適用「普／中／高」、查核型態（source/hybrid/external）、證據方向與原 70 項相關規則。
- **不得修改或重新編號原 70 項，也不得將 80 項加總成 150 個 Code Review 規則**。佇列 `next_checks[].system_baseline_v13_controls` 是源碼檢查參照；對 source/hybrid 可閱讀程式碼與設定，external 需政策、正式工具掃描、滲透測試、部署、演練或營運紀錄。將已檢查方向及待補證據註記於相關 70 項的審查摘要，不得謊稱已完成獨立驗證。
- 系統防護需求等級「普／中／高」（附表九／十）**與**機關責任等級「A～E」不同。依 `project.protection_demand_level` 及 `protection_demand_level_basis` 取得正式依據決定適用數（普 45、中 62、高 80）；若證據不足則不填值或設為「待確認」，不可因看見特定程式碼而推定正式級別。
- `report.json.system_baseline` 與 HTML 的獨立章節記錄各項狀態。不提供另外的真實驗證資料時，自動標示 `pending_level`／`not_assessed`／`not_applicable_by_level`；**既有 70 項 Pass 不會推論成防護基準 Pass**。
- 在受測專案的 `reports/security-code-review/baseline_assessment.json` 可記錄經實際核對的獨立項目：`{ "controls": [{ "id": "TW-SB-2.1.3.2", "status": "review", "reason": "已檢查原始碼，尚待實機授權測試", "reviewer": "審核人員", "verified_on": "2026-10-20", "evidence": [] }] }`。需完整理由、日期和審核者，`pass/fail` 更須有具體獨立佐證路徑或外部工件編號。
- 只對確實完成的項目寫入人工決定，無佐證不得填 `pass`；也不要把人工基準結果寫進原有 `assessment.json.checks`。如果舊版報告已有 Finding 或已審查結果，一律保留；補充基準不須清空原紀錄。
- PDF 的附件一僅見起始頁，未取得完整附件，故對照以第 2 章 80 項內容為準；不是聲稱已比對完整附表影本。
- `complete_review.py` 仍在受測專案執行，沿用 `$security-code-review`。只有 70/70 審查完成才產生報告；獨立防護基準項目可保留待確認，不影響既有交付條件，但不可對外宣稱整體符合性驗證完成。

## WEB 應用程式安全參考指引 V3.2（限定 ASP.NET/.NET 與通用 Web 安全）

- 來源：《WEB應用程式安全參考指引》V3.2（114/12/31），第 4 章七構面、29 類控制、35 個明確細部技術條次；以 `standards/nics-web-guide-v3.2.yaml` 記錄章節、PDF 頁碼、審查方向與相關原 70 項規則。**這是技術參考，不是獨立 29/35 條新增完成規則、不是法定符合性結果**。
- **使用者排除 Java、PHP 實作技術**：不得使用此 V3.2 指引中的 Java/Servlet/JSP 或 PHP 語法、設定範例、函式庫或專屬檢測命令來設計檢核；僅採用 ASP.NET/.NET 的實作建議以及與語言無關的 Web 安全要求。這不代表遇到其他語言時跳過既有 70 項通用安全檢查。
- 對佇列 `next_checks[].web_guide_v32_checks` 的適用項目，實際核查程式碼路徑／行號及設定；V3.2 的細部條次含 `observed_levels` 與原 PDF 表格依據，只表示該節實作建議表至少一項涉及的普／中／高等級（同節多項可能適用不同等級），不得直接推定整個控制適用或自動 N/A；在 `decision_reason`／`execution.summary` 記錄相應 `NICS-WEB-4.x.x[.x]` ID、證據、不能確認的外部事項，並保持既有 Finding 與 70/70 計數。
- V3.2 新增 `4.5.3.4 HTTP 安全標頭`：需對照 `CR-05` 審查 CSP、HSTS、nosniff、X-Frame-Options、Referrer-Policy、Permissions-Policy 的實際設定與有效性；**文件部分 CSP 範例含 unsafe-inline / unsafe-eval，不能照抄或以有設定標頭即宣稱安全**。HSTS 與實際回應標頭可能仍需部署佐證。
- 指引第 3 章使用 OWASP Top 10:2021，保留歷史版本；既有 OWASP Top 10:2025 仍為獨立新版本分類。
- PDF 共 253 頁，末頁僅列附件 1～3 標題，**本次沒有完整附件內容**；不得把附件中的檢核表或設定附錄視為已驗證。
- `report.json.web_guide_v32` 與離線 HTML 的「WEB 應用程式安全參考指引 V3.2 技術對照」只呈現來源、技術範圍、控制映射及查核焦點；原始碼檢核結果與 V1.3 防護基準獨立呈現，不依映射自動推論合規。

## 自動審查流程

**重要：本 Skill 的使用者交付物是 70 項完整資安審查報告，不是弱點速報、待辦清單或要求先修復的建議。**
單次執行須主動持續查核直到 70 項完成且 HTML／JSON 驗證通過；僅有真正無法繼續的環境／工具錯誤才停止。
不得因發現 1～3 項風險、完成少量來源查證、缺少外部部署資訊或看到仍有 pending 就結束並要求使用者再次呼叫 Skill。

### 必須執行的佇列迴圈（Codex／Claude Code）

1. 以 `SKILL_ROOT` 為腳本位置、`TARGET_ROOT` 為受測專案，**立即**執行：
   ```bash
   python <SKILL_ROOT>/scripts/review_queue.py --target <TARGET_ROOT> --init --batch-size 10
   ```
   此命令只在檔案不存在時建立 70 項 pending 草稿；已存在的 assessment.json、findings、project.json 一律保留。**pending 是待執行工作清單，不是完成結果**。
2. 使用工具輸出的 `next_checks`、`search_targets`、`inspection_hints` 和適用條件，在 `TARGET_ROOT` **逐條真正查核**該批規則：搜尋、唯讀原始碼檢視、追蹤呼叫與組態、紀錄各項證據、方法和判定理由。找到疑似弱點就直接建立 `assessment.findings[]`，並正確關聯 `check_ids`／`finding_ids`；**不修改程式、不要求先修復、不停止迴圈**。已查核但部署或動態測試仍待確認的規則可記為 `status=review`、`execution.state=completed`，但需具體紀錄哪些部分已查核、哪些資訊缺少。
3. **每完成一項／每批立即保存** `TARGET_ROOT/reports/security-code-review/assessment.json`，保持既有 Findings 與其他已完成項目，不得將已知風險清空；然後再次執行上方佇列命令（不必重新初始化也可移除 `--init`）。
4. 如果 `ready_for_report=false`，**回到步驟 2，繼續執行剩餘規則**。不可將 `next_checks` 當作僅供建議、不可把「已保存進度／下次續跑」當成正常成功輸出。只有 `ready_for_report=true`（70/70）才進入報告產生。若遇到真正阻斷錯誤，先保存已完成的檢核、明確報告錯誤與不能繼續的原因；不可聲稱全部完成。
5. 由 Agent 內部呼叫 `complete_review.py`，產出最終 `CodeReview_YYYYMMDD.html`、`report.json` 並驗證。最終答覆優先交付這兩個路徑、70 項狀態摘要與 Finding 數；改善建議應收錄於報告中，不要在最終訊息中先要求修復。

**注意**：`review_queue.py` 只負責初始化、呈現下一批規則及進度計數，不會自行完成原始碼的 70 項判斷。Agent 必須實際使用程式碼／設定證據逐項分析；不得把佇列已列出 70 個 ID 當作審查完成。


1. 讀取 `standards/standards-register.yaml`、`policies/applicability-matrix.yaml` 與 `rules/{AC,AU,IN,CR,EH,LG,DP,PD,BC,SI}.yaml`，共 70 項；不得跳過、增加或重編 ID。
2. 盤點 `TARGET_ROOT` 的語言、框架、認證授權、資料流、儲存、相依套件、部署與 CI/CD；根據 `profiles/project-profile.example.yaml` 辨識適用情境。排除 `.git/`、`reports/`、`.agents/skills/`、`.claude/skills/` 與生成物／相依套件目錄，避免把 Skill 本身當成受測程式碼；不要排除專案的 CI 設定。缺乏政策資料時不擅自決定法規適用級別。
3. **必須按前述佇列迴圈逐項完成 70 項檢核，不能只填入 70 個 ID 或一律設為 review 就結束。** 依每條規則的 `inspection.search_targets`、`applicability` 與證據要求搜尋目標專案、追蹤程式碼呼叫鏈並核對組態；可分批掃描，但必須持續直到 70 項各自完成，才允許產製報告。一次呼叫應自動持續，不因找到高風險問題而暫停。每完成一組就將結果保存到受測專案的 `reports/security-code-review/assessment.json`，重新啟動時先載入已查核結果並僅補做尚未完成的 ID；不得憑空標記完成。
   - 對每項填寫 `execution: {state, methods, summary, inspected_paths?}`；掃描中為 `pending`，已實際執行檢核才標 `completed`，出現無法進行的真正錯誤標 `blocked`。
   - `status` 仍為 `pass`、`fail`、`review` 或 `na`。**review 代表已分析但仍缺部署／政策／人工／動態佐證**，需記錄已完成分析與待補證據，不等於尚未審查；不可隨意推定 pass。
   - **審查是識別風險並產出報告，不是修復程式。** 發現密碼鎖定、例外訊息、TOTP 或任何疑似漏洞時，立即將已確認風險保存為 `assessment.findings[]`、將相應檢核狀態更新為 `fail` 或證據尚不足時 `review`，並保存檔案、行號、佐證、影響、改善建議與信心水準。接著**繼續剩餘檢核**，不得把「需要優先處理／修復」當作停止掃描、要求使用者先改程式或提前交付部分結果的理由。風險優先級僅用於最後報告排序，所有改碼與修補皆屬後續獨立工作。
   - 缺少部署、政策、外部證據或動態測試時，標記已完成靜態查核的 `review` 並說明仍待確認的範圍；不得因該項缺證據而停止其餘檢核。
   - **唯讀解碼已獲本 Skill 的一般執行授權，不得再次詢問使用者可否讀取 CP950／CP1252。** 先依 BOM 使用 UTF-8-BOM／UTF-16 等編碼，無 BOM 優先 UTF-8，失敗則自動嚴格回退 CP950、CP1252。回退警告只需記入診斷／報告限制，**不是人工確認閘門**；疑似誤判編碼時以其他線索核對，不得默默扭曲證據。可使用 `python <SKILL_ROOT>/scripts/source_reader.py --source-root <TARGET_ROOT> --path <相對來源檔> --start 1 --end 200` 取得帶行號的唯讀內容，不得修改來源、忽略解碼錯誤位元組或憑空填證據。
   - 如果個別來源仍無法安全解碼，記錄檔案與解碼錯誤並繼續其他可讀檔案與檢核；只有對完成剩餘審查構成實質阻斷的錯誤才能中斷，並清楚列出未完成範圍。
   - 缺乏證據不得 Pass；N/A 須有理由；不得自動執行破壞性測試或捏造動態測試、環境與政策簽核。
### 必須記錄審查範圍與檔案明細

- 在 `assessment.scope_details.projects` 記錄真正納入的專案：每項具有 `name` 及相對 `TARGET_ROOT` 的 `path`；單一專案可使用 `path: "."`，多專案各列一筆。不要由 manifest 數直接推定審查專案數。
- 在 `scope_details.excluded_paths` 可記錄額外排除的目錄／檔案及 `reason`；不得排除仍被列為已審查的檔案；專案 CI 設定不能預設排除。
- 每項 completed 規則，將**實際閱讀、追蹤與核對**的相對來源路徑填入 `execution.inspected_paths`；單純搜尋命中或盤點檔名不算已審查，不能大量填入尚未實際閱讀的路徑。
- `complete_review.py` 自動盤點工作目錄、計算排除數，並以 completed 的 `inspected_paths` 去重計算實際審查檔數與專案數、檔案類型及明細；路徑不存在、跨出目錄或位於排除範圍時不可通過驗證。無專案對照時應標示「未提供」而非猜測數字。

4. 在 **受測專案**（非 Skill）建立 `reports/security-code-review/`，並寫入：
   - `assessment.json`：符合 `schemas/assessment.schema.json` 的 70 項檢核、已驗證 Finding、真實 Git Revision 與證據。
   - `project.json`：本系統的顯示資料，至少 `name` 與 `language_framework`。Agent **須在 70 項程式碼審查時同步嘗試法定 A～E 級的初步研判**，不先要求使用者填級別，亦不因缺少資訊中斷審查。依《資通安全責任等級分級辦法》第 4～10 條查證已實際讀取的程式碼、權限區分、設定、設計及業務文件與服務覆蓋範圍；證據充足時寫入 `project.security_level_assessment`，包含 `status:"preliminary"`、`level:"A～E之一"`、`basis`（規定條次及具體理由）、`evidence:[{path,line_start,line_end}]`（須已列入 completed 的 inspected_paths）及 `missing_information`。不可僅憑登入功能、漏洞數推定 A／B 級；C 級權限管理只是第 6 條**技術條件線索**，尚需確認機關維運事實及更高級別是否適用；未找到權限程式碼不能推斷 D／E 級。
   - 若證據不足，Agent 應記錄 `security_level_assessment: {status:"undetermined",level:"待確認",basis:"無法判定原因",evidence:[],missing_information:["待核對機關業務及核定資料"]}`，報告顯示說明，**不詢問使用者且繼續其餘 70 項審查**。若未填初判，報告產生器自動檢視 completed 規則的 inspected_paths，以具體角色／權限管理程式碼提出 C 級技術線索，否則自動記錄「待確認」原因。
   - `security_level`（A～E）只用於已提供的**正式**認定／核定資料，並需 `security_level_basis`；AI 初判不得寫入此欄。正式分級優先顯示，與程式碼整體風險、資通系統防護需求分級分開。
   - `presentation.json`（選用）：真實審查方法／限制、改善優先序及 Before / After。不可補造程式碼、風險或安全優點。
5. **只有 70 項 `execution.state=completed` 才能開始報告階段。** 從 `TARGET_ROOT` 作為工作目錄，由 Agent 自動呼叫：

   ```bash
   python <SKILL_ROOT>/scripts/complete_review.py --target <TARGET_ROOT>
   ```

   Windows Python Launcher 可使用 `py -3` 代替 `python`。程式從 `SKILL_ROOT` 載入規則、Schema 和 HTML 模板，將所有報告寫在 `TARGET_ROOT/reports/security-code-review/`，並串接原有檢核 JSON、HTML 生成及最終驗證。
6. 若 Python 或相依套件尚未安裝，清楚提示一次性安裝指令 `python -m pip install -r <SKILL_ROOT>/requirements.txt`，**不要自行變更全域環境或假稱 HTML 已產生**。如果工具執行環境允許隔離虛擬環境，可先取得使用者許可再安裝。
7. 逐項確認 `completed` 數量為 70 才執行報告程序。若仍有 `pending`／`blocked`，必須主動執行佇列迴圈查核其餘項目；**只有真正無法繼續的執行阻礙才回報中斷**，並列出已保存的進度與確切錯誤，不得因一般審查工作尚多就結束。**不要以 3 個優先弱點或部分分析代替最終 HTML／JSON**。只有三階段程式都返回 0，才能回報 HTML／JSON 已驗證；列出實際路徑、弱點數與未能驗證的範圍。原始碼取證須填相對 `TARGET_ROOT` 的檔案與真實行號，避免輸出 Token、密碼與個資。

## 報告輸出位置

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
