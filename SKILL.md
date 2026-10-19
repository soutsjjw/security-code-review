---
name: security-code-review
version: 2.1.4-rc1
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

## 自動審查流程

1. 讀取 `standards/standards-register.yaml`、`policies/applicability-matrix.yaml` 與 `rules/{AC,AU,IN,CR,EH,LG,DP,PD,BC,SI}.yaml`，共 70 項；不得跳過、增加或重編 ID。
2. 盤點 `TARGET_ROOT` 的語言、框架、認證授權、資料流、儲存、相依套件、部署與 CI/CD；根據 `profiles/project-profile.example.yaml` 辨識適用情境。排除 `.git/`、`reports/`、`.agents/skills/`、`.claude/skills/` 與生成物／相依套件目錄，避免把 Skill 本身當成受測程式碼；不要排除專案的 CI 設定。缺乏政策資料時不擅自決定法規適用級別。
3. **必須實際逐項執行 70 項檢核，不能只填入 70 個 ID 或一律設為 review 就結束。** 依每條規則的 `inspection.search_targets`、`applicability` 與證據要求搜尋目標專案、追蹤程式碼呼叫鏈並核對組態；可分批掃描，但必須持續直到 70 項各自完成，才允許產製報告。一次呼叫應自動持續，不因找到高風險問題而暫停。每完成一組就將結果保存到受測專案的 `reports/security-code-review/assessment.json`，重新啟動時先載入已查核結果並僅補做尚未完成的 ID；不得憑空標記完成。
   - 對每項填寫 `execution: {state, methods, summary, inspected_paths?}`；掃描中為 `pending`，已實際執行檢核才標 `completed`，出現無法進行的真正錯誤標 `blocked`。
   - `status` 仍為 `pass`、`fail`、`review` 或 `na`。**review 代表已分析但仍缺部署／政策／人工／動態佐證**，需記錄已完成分析與待補證據，不等於尚未審查；不可隨意推定 pass。
   - **審查是識別風險並產出報告，不是修復程式。** 發現密碼鎖定、例外訊息、TOTP 或任何疑似漏洞時，立即將已確認風險保存為 `assessment.findings[]`、將相應檢核狀態更新為 `fail` 或證據尚不足時 `review`，並保存檔案、行號、佐證、影響、改善建議與信心水準。接著**繼續剩餘檢核**，不得把「需要優先處理／修復」當作停止掃描、要求使用者先改程式或提前交付部分結果的理由。風險優先級僅用於最後報告排序，所有改碼與修補皆屬後續獨立工作。
   - 缺少部署、政策、外部證據或動態測試時，標記已完成靜態查核的 `review` 並說明仍待確認的範圍；不得因該項缺證據而停止其餘檢核。
   - **唯讀解碼已獲本 Skill 的一般執行授權，不得再次詢問使用者可否讀取 CP950／CP1252。** 先依 BOM 使用 UTF-8-BOM／UTF-16 等編碼，無 BOM 優先 UTF-8，失敗則自動嚴格回退 CP950、CP1252。回退警告只需記入診斷／報告限制，**不是人工確認閘門**；疑似誤判編碼時以其他線索核對，不得默默扭曲證據。可使用 `python <SKILL_ROOT>/scripts/source_reader.py --source-root <TARGET_ROOT> --path <相對來源檔> --start 1 --end 200` 取得帶行號的唯讀內容，不得修改來源、忽略解碼錯誤位元組或憑空填證據。
   - 如果個別來源仍無法安全解碼，記錄檔案與解碼錯誤並繼續其他可讀檔案與檢核；只有對完成剩餘審查構成實質阻斷的錯誤才能中斷，並清楚列出未完成範圍。
   - 缺乏證據不得 Pass；N/A 須有理由；不得自動執行破壞性測試或捏造動態測試、環境與政策簽核。
4. 在 **受測專案**（非 Skill）建立 `reports/security-code-review/`，並寫入：
   - `assessment.json`：符合 `schemas/assessment.schema.json` 的 70 項檢核、已驗證 Finding、真實 Git Revision 與證據。
   - `project.json`：本系統的顯示資料，至少 `name` 與 `language_framework`。
   - `presentation.json`（選用）：真實審查方法／限制、改善優先序及 Before / After。不可補造程式碼、風險或安全優點。
5. **只有 70 項 `execution.state=completed` 才能開始報告階段。** 從 `TARGET_ROOT` 作為工作目錄，由 Agent 自動呼叫：

   ```bash
   python <SKILL_ROOT>/scripts/complete_review.py --target <TARGET_ROOT>
   ```

   Windows Python Launcher 可使用 `py -3` 代替 `python`。程式從 `SKILL_ROOT` 載入規則、Schema 和 HTML 模板，將所有報告寫在 `TARGET_ROOT/reports/security-code-review/`，並串接原有檢核 JSON、HTML 生成及最終驗證。
6. 若 Python 或相依套件尚未安裝，清楚提示一次性安裝指令 `python -m pip install -r <SKILL_ROOT>/requirements.txt`，**不要自行變更全域環境或假稱 HTML 已產生**。如果工具執行環境允許隔離虛擬環境，可先取得使用者許可再安裝。
7. 逐項確認 `completed` 數量為 70 才執行報告程序。若仍有 `pending`／`blocked`，應優先繼續查核其餘項目；僅真正的執行阻礙或工作階段限制才回報中斷，並列出已保存的進度及續跑方式。**不要以 3 個優先弱點或部分分析代替最終 HTML／JSON**。只有三階段程式都返回 0，才能回報 HTML／JSON 已驗證；列出實際路徑、弱點數與未能驗證的範圍。原始碼取證須填相對 `TARGET_ROOT` 的檔案與真實行號，避免輸出 Token、密碼與個資。

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

- 使用者只下達一次 `$security-code-review`；Agent 應自行分析、持續審查與產生報告，不因風險發現或唯讀編碼回退詢問「是否繼續／是否先修復／是否允許解碼」。
- 分批完成 70 項時，持續更新暫存審查資料。只有實際檢核完成才能把 `execution.state` 由 `pending` 改成 `completed`。
- Finding 的 `remediation` 只代表建議，**不得以執行本 Skill 為由修改受測程式碼**；若未能確認可利用性，清楚寫明靜態檢核與部署／動態測試限制。
- 最終報告包含所有已發現 Finding；嚴重弱點可列於改善優先序，但不能排擠其他 70 項檢核。

## 禁止事項

- 不將受測專案的 JSON 或 HTML 寫入 Skill 安裝目錄。
- 不複製其他系統的審查結果或使用示範檔作為正式證據。
- 不將 OWASP Top 10 風險類別宣稱為直接合規條文；經核准的風險例外不會自動讓 Fail 變 Pass。
- 不以 Schema／HTML 驗證通過來宣稱漏洞已完成動態測試或政策簽核。
