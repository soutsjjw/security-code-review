---
name: security-code-review
version: 2.1.3-rc1
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
3. **必須實際逐項執行 70 項檢核，不能只填入 70 個 ID 或一律設為 review 就結束。** 依每條規則的 `inspection.search_targets`、`applicability` 與證據要求搜尋目標專案、追蹤程式碼呼叫鏈並核對組態；可分批掃描，但必須持續直到 70 項各自完成，才允許產製報告。
   - 對每項填寫 `execution: {state, methods, summary, inspected_paths?}`；掃描中為 `pending`，已實際執行檢核才標 `completed`，出現無法進行的真正錯誤標 `blocked`。
   - `status` 仍為 `pass`、`fail`、`review` 或 `na`。**review 代表已分析但仍缺部署／政策／人工／動態佐證**，需記錄已完成分析與待補證據，不等於尚未審查；不可隨意推定 pass。
   - 不因單項缺外部證據停止整體審查；繼續其他項目並將該項 `execution.state` 設為 `completed`、`status=review`。真正阻斷錯誤才停止並回報未完成項。
   - 唯讀處理混合編碼：UTF-8、UTF-8-BOM、含 BOM 的 UTF-16，以及嚴格解碼的 CP950／CP1252 回退，回退時需警告並確認。不得修改來源編碼、忽略錯誤位元組或憑空填寫來源證據。
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
7. 若任何檢核仍為 `pending`／`blocked` 或內容只是未執行佔位文字，必須繼續執行或回報阻斷錯誤，不可跳過。只有三階段程式都返回 0，才能回報 HTML／JSON 已驗證；列出 HTML 與 JSON 的實際完整路徑及未能驗證的範圍。原始碼取證須填相對 `TARGET_ROOT` 的檔案與真實行號，避免輸出 Token、密碼與個資。

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

## 禁止事項

- 不將受測專案的 JSON 或 HTML 寫入 Skill 安裝目錄。
- 不複製其他系統的審查結果或使用示範檔作為正式證據。
- 不將 OWASP Top 10 風險類別宣稱為直接合規條文；經核准的風險例外不會自動讓 Fail 變 Pass。
- 不以 Schema／HTML 驗證通過來宣稱漏洞已完成動態測試或政策簽核。
