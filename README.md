# Security Code Review

以 **70 項資安規則**進行原始碼審查的 Codex／Claude Code Skill，支援分批續跑、弱點證據紀錄，以及可離線檢視的 HTML／JSON 報告。

**規則集：v2.0.0（正式版）** · **Skill：v2.2.0-rc1** · **審查規則：70 項**

規則集現可直接作為本專案正式版本使用，**不需要先取得公司資安核定**。這不代表任何受測系統已符合所有法規，也不取代特定系統的正式分級、政策核准或第三方測試。

## 快速開始

安裝 Skill 後，在**受測專案的 Codex 對話**中輸入：

```text
$security-code-review
```

或指定目標路徑：

```text
$security-code-review /path/to/project
```

也可指定子目錄，例如 `$security-code-review src/Api`。Claude Code 使用 `/security-code-review`。

> 以上是 **Agent 對話指令**，不是 PowerShell／Bash 指令。請在受測專案工作目錄啟動 Agent；規則與工具位於 Skill 安裝目錄，審查結果則寫回受測專案。

Agent 會盤點程式碼、逐條審查、保留既有進度與 Finding，直到 **70/70 項皆實際完成**，才驗證並交付正式報告。遇到缺乏部署、政策或動態證據時，須記錄已完成的靜態分析與待確認事項；不會因此清空既有結果、要求先修補弱點或提前交付部分報告。

## 安裝

| 使用環境 | Skill 放置路徑 |
|---|---|
| Codex（全域） | `~/.agents/skills/security-code-review/` |
| Codex（單一專案） | `<專案>/.agents/skills/security-code-review/` |
| Claude Code（全域） | `~/.claude/skills/security-code-review/` |
| Claude Code（單一專案） | `<專案>/.claude/skills/security-code-review/` |

Windows 的 Codex 全域路徑為 `%USERPROFILE%\.agents\skills\security-code-review\`。下載 ZIP 並複製**整個儲存庫**也可以；若已有 GitHub 存取權限，可直接安裝 `develop`：

macOS／Linux（Codex 全域）：

```bash
mkdir -p "$HOME/.agents/skills"
git clone --branch develop https://github.com/soutsjjw/security-code-review.git "$HOME/.agents/skills/security-code-review"
```

Windows PowerShell（Codex 全域）：

```powershell
New-Item -ItemType Directory -Force "$env:USERPROFILE\.agents\skills" | Out-Null
git clone --branch develop https://github.com/soutsjjw/security-code-review.git "$env:USERPROFILE\.agents\skills\security-code-review"
```

安裝後重新開啟 Agent 工作階段。

完成 HTML／JSON 報告產生與驗證，需要 **Python 3.10+**。Agent 會自動依序偵測 `python`、`python3`、`py -3`，並核對 `requirements.txt` 套件與版本。無需因 Windows 找不到 `python` 就直接中斷；若其他指令可用且環境完整，會自動繼續。

可在 Skill 安裝目錄先進行唯讀環境檢查：

macOS／Linux：
```bash
sh scripts/run-python.sh --check
```

Windows PowerShell：
```powershell
& ".\scripts\run-python.cmd" --check
```

若提示缺少套件，使用可用的 Python 安裝一次，例如 `python3 -m pip install -r requirements.txt`，Windows 亦可使用 `py -3 -m pip install -r requirements.txt`。若完全沒有 Python，先於 **Agent 實際執行的環境**安裝 Python 3.10+。Skill **不會自行安裝套件或覆寫既有審查進度**；環境未就緒時會明確回報原因。

Python 負責佇列、輸出及驗證，**不是由 Python 自動完成原始碼安全審查**；實質查核仍由 Agent 執行。環境設定完成後，一般使用者不必手動執行報告生成腳本。

## .NET 專用結構索引與省 Token 模式

本階段的程式碼分析器僅支援 **.NET Core／現代 .NET C# 專案**；傳統 .NET Framework 與 Vue 分析器已預留擴充架構，但目前**不宣稱已支援**。混合或未辨識技術專案會停止，不會假裝完成掃描。70 項規則、逐檔真實證據、100% 來源覆蓋率、HTML／JSON 報告維持不變。

- **CodeGraph 選用**：有 CLI 且受測專案已執行 `codegraph init` 建立索引，Agent 優先使用程式碼圖譜；沒有則自動使用原有來源查核。Skill 不自行安裝或建立索引。CodeGraph 官方文件：<https://github.com/colbymchenry/codegraph>。
- **Roslyn 選用**：安裝 .NET SDK 8+ 時，Agent 會在暫存目錄利用 SDK 內附 Roslyn 建立 C# 語法／方法／呼叫候選索引，不修改受測原始碼；沒有 SDK 則降級查核。Roslyn 索引不是弱點結論。
- **完整＋增量**：結構結果保存在 `reports/security-code-review/analysis/structure-index.json`；未變動檔案重用語法索引，有來源變更且缺乏可信跨檔案依賴閉包時保守列出全部重新檢查。既有 `assessment.json`、Findings 不會由索引覆寫。
- **精簡佇列**：預設由 Agent 使用 `review_queue.py --compact`，實際處理規則時再用 `--detail-id <規則ID>` 取完整查核方向。
- **Token 統計**：僅記錄執行器實際提供的 Token 計數，不提供虛構的節省比例。

索引前置命令由 Skill 自動呼叫；進階參數及限制請見 [進階使用說明](docs/advanced-usage.md)。

## 單代理安全審查完整性守門

本次強化仍採用**單代理逐檔審查**，沒有加入子代理分工或平行處理。現有 Roslyn／CodeGraph 來源索引新增 DI、Middleware、組態、Endpoint 與跨專案候選；70 項規則都要檢查，跨檔與全專案規則另需完成控制鏈與責任結案。

`analysis_prepare.py` 建立 Git／SHA256 固定來源快照。審查中結果透過 `review_safety.py` 獨立暫存、整合與衝突檢查；只在來源快照一致、跨檔與全專案補查已結案、既有逐檔覆蓋和規則證據驗證都通過後，才交付正式報告。現有 `assessment.json` 與 HTML／JSON 格式不變；既有 Findings 不得被新結果覆蓋或清除。

Agent 會自動操作新增工具。詳細的恢復方式、結案格式及指令見 [完整性守門操作指引](docs/review-integrity-guards.md)。

## 單代理第二輪反向複核

第一輪完成 70 項、100% 來源檢閱與安全控制／外部證據查核後，先執行 `review_safety.py --begin-second-pass` 固定第一輪判定與快照，再由同一代理重新閱讀程式碼、尋找反例及紀錄矛盾裁決。第二輪須覆核全部 70 項，未完成不得交付正式報告；此程序不等於真正獨立代理審查。詳見 [單代理反向複核指引](docs/adversarial-second-pass.md)。

## 檢核依據

| 規範／檢核層 | 數量 | 用途 |
|---|---:|---|
| **核心原始碼安全規則** | **70 項** | 唯一的核心規則與 70/70 完成進度 |
| TACERT《網站安全管理指南》V2 | 39 個補充焦點 | 對照核心規則，補強網站管理及維運檢查 |
| OWASP Top 10:2025 | 10 類風險 | 風險分類與未涵蓋項目提示，非獨立合規判定 |
| 《資通系統防護基準驗證實務》V1.3 | 80 項 | 獨立防護基準查證（普45／中62／高80） |
| 《WEB應用程式安全參考指引》V3.2 | 29 類、35 個細部條次 | ASP.NET／.NET 與通用 Web 技術審查依據 |
| V3.2 附件 1 | 55 項 | Web 安全查檢表（普33／中44／高55） |
| V3.2 附件 3 | 6 項標頭 | 強化 `CR-05`，另關聯 `CR-01`／`IN-02` |

**數量不可加總為新的程式碼規則數。** 原有 70 項仍是程式碼審查核心，其他規範屬風險對照、技術提示或獨立證據驗證。找不到必要部署／制度／實測證據時，不得宣稱已完全符合。

V3.2 主文件與附件保留 **ASP.NET／.NET、IIS 與通用 Web 安全要求，排除 Java／PHP 專屬實作**。歷史文件所引用的 OWASP Top 10:2021 仍維持原版本；另以 OWASP Top 10:2025 做風險分類。

詳細來源及檢核目錄請見 [規範登錄](standards/standards-register.yaml)、[70 項規則](docs/70-rules-standardized.md)。

標準專屬審查指引已從 `SKILL.md` 拆分到 `docs/`：[TACERT V2](docs/tacert-v2-review.md)、[OWASP 2025](docs/owasp-top10-2025-review.md)、[防護基準 V1.3](docs/system-baseline-v1.3-review.md)、[WEB 指引 V3.2](docs/web-guide-v3.2-review.md)、[附件 1](docs/web-guide-v3.2-appendix1-review.md)、[附件 3](docs/web-guide-v3.2-appendix3-review.md)。Agent 執行 `review_queue.py --detail-id <規則ID>` 後，依 `standard_documents` 載入該規則實際對應的文件；共同證據、Pass／Fail／Review／N/A 與交付硬性規則仍以 `SKILL.md` 為準。

## 報告與審查狀態

正式結果保存在**受測專案**，不寫入 Skill 目錄：

```text
<受測專案>/
└── reports/security-code-review/
    ├── assessment.json              # 70 項結果、進度及 Findings
    ├── project.json                 # 系統資訊及分級依據
    ├── presentation.json            # 選填：報告顯示資訊
    ├── report.json                  # 最終 JSON 報告
    ├── CodeReview_YYYYMMDD.html     # 最終離線 HTML 報告
    ├── baseline_assessment.json     # 選填：V1.3 防護基準證據
    ├── web_appendix1_assessment.json # 選填：V3.2 附件 1 查證
    └── web_appendix3_assessment.json # 選填：六項標頭實際回應查證
```

核心規則狀態有 `pass`、`fail`、`review`、`na`。正式審查的每項 `pass/fail/review` 必須提供可定位的來源行號或設定／測試／外部證據工件；批次模板、單純檔案路徑或空泛的 `other` 描述不能代表完整審查。其中 `review` 表示**已檢查可查證的部分，但仍缺外部證據**；與執行進度 `execution.state=pending/completed/blocked` 是不同欄位。只有全部 70 項 `completed`、**應審查來源檔案全數完成逐檔核對**，且 HTML／JSON 驗證通過，才算完成正式交付。

佇列輸出的 `source_coverage` 會顯示應審查原始碼／設定檔總數、已審查數、未審查數及類型，並以 `next_source_paths` 指示下一批漏查來源；若僅審查 13／660 個 `.cs`，即使 70 項規則均標記完成，也**禁止交付正式報告**。**逐檔檢核需評估所有 70 條規則的適用性，不能只取第一個關鍵字命中結果；不可將稽核、個資、相依套件等錯誤對應至不相關的 `XX-01`。** 使用重複的不適用理由或大量制式摘要會被驗證器拒絕，但不會強制每檔至少對應兩條規則。\n\n完成來源檔案核對後，須記錄 `assessment.file_reviews` 的 SHA256、逐檔 10 類適用性判斷、檢核依據與來源行號，並與 `execution.inspected_paths` 對應；不能將搜尋命中或清單盤點當成完成審查。缺少逐檔紀錄、來源異動或規則關聯不一致時會拒絕正式報告（[資料格式](docs/file-review-contract.md)）。個別 `review` 必須具體列出已審查證據與未能確認原因，證據可支持 `fail` 時須記錄 Finding，不能將 `review` 當成尚未分析的預設結論。

報告會自動概述實際審查的**專案數、檔案數及檔案類型**，顯示現行規則版本（保留舊紀錄版本）、執行工具、保守個資初判、待確認資訊及依 Finding 證據推導的**整體靜態風險初判**；證據不足時不猜測，也不要求先人工核定。報告另保留弱點證據、未涵蓋範圍及適用規範。對機關**責任等級 A～E**，可根據實際檢閱的資料產生初步研判；無足夠依據就標示待確認，不能當作正式法定核定。個別系統的**防護需求分級（普／中／高）**另行記錄，不能從 A～E 換算。

> 既有 `2.0.0-rc1` 的 `assessment.json` 可繼續使用，原有 Findings 與進度保留。其審查結果不會因正式版升級就自動宣稱已檢查新增的規範對照。

## 進階操作與維護

- [完整審查指令（/goal）、批次續跑與報告流程](docs/advanced-usage.md)
- [分級、證據及例外管理原則](docs/standardization-policy.md)
- [審查資料結構](docs/data-contract.md) · [HTML／JSON 報告結構](docs/report-schema-contract.md)
- [Skill 執行指示](SKILL.md)

維護者可在 **Skill 根目錄**執行：

```bash
python scripts/validate_package.py
python -m unittest discover -s tests -v
```

這些測試驗證規則一致性與資料流程，不代表已對特定受測系統執行滲透測試或取得資安合規認證。
