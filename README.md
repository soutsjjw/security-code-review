# Security Code Review

以 **70 項資安規則**進行原始碼審查的 Codex／Claude Code Skill，支援分批續跑、弱點證據紀錄，以及可離線檢視的 HTML／JSON 報告。

**規則集：v2.0.0（正式版）** · **Skill：v2.1.9** · **審查規則：70 項**

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

完成 HTML／JSON 報告產生與驗證，需要 **Python 3.10+**，並在 Skill 安裝目錄執行一次：

```bash
python -m pip install -r requirements.txt
```

Python 用於輸出與驗證，**不是由 Python 指令自動完成原始碼安全審查**；實質查核仍由 Agent 執行。安裝完成後，一般使用者不必手動執行報告生成腳本。

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

核心規則狀態有 `pass`、`fail`、`review`、`na`。其中 `review` 表示**已檢查可查證的部分，但仍缺外部證據**；與執行進度 `execution.state=pending/completed/blocked` 是不同欄位。只有全部 70 項 `completed` 且 HTML／JSON 驗證通過，才算完成正式交付。

報告會顯示實際審查的**專案數與檔案數**、弱點證據、未涵蓋範圍及適用規範。對機關**責任等級 A～E**，可根據實際檢閱的資料產生初步研判；無足夠依據就標示待確認，不能當作正式法定核定。個別系統的**防護需求分級（普／中／高）**另行記錄，不能從 A～E 換算。

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
