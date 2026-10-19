# Security Code Review Skill v2.1.3

公司跨系統共用的 **70 項資安原始碼審查 Skill**。在被審查專案呼叫一次，Agent 執行檢核並產生可離線開啟的 HTML／JSON 報告。規則集 `2.0.0-rc1` 尚待公司資安核定。

## 快速使用

1. 安裝本 Skill（見下節），重新開啟 Codex／Claude Code 工作階段。
2. **開啟欲檢查的專案目錄**，在 Codex 對話輸入：

   ```text
   $security-code-review
   ```

   或指定另一個專案：

   ```text
   $security-code-review /path/to/project
   ```

   也可以指定檢核範圍，如 `$security-code-review src/Api`。Claude Code 改用 `/security-code-review`。**這是 Agent 的聊天指令，不是 PowerShell／Bash 的系統命令。**
3. Agent 自動盤點專案、**逐項完成 70 項實際檢核**，將 `assessment.json` 和專案資訊寫在受測專案內，再呼叫 Python 產生與驗證報告。

**報告一律輸出至受測專案，不會寫入安裝的 Skill 資料夾：**

```text
你的專案/
└── reports/security-code-review/
    ├── assessment.json
    ├── project.json
    ├── presentation.json      # 有佐證時才產生
    ├── report.json
    └── CodeReview_YYYYMMDD.html
```

已查核但缺少外部環境、部署與人工佐證的控制項可標 `review`，不可將尚未執行者填為 `review`。每項須附 `execution`（`state`、`methods`、`summary`、可選 `inspected_paths`）；正式報告僅接受全部 `completed`。

## 安裝（只需一次）

**Codex 全域共用**：將整個 `security-code-review/` 資料夾放到 `~/.agents/skills/security-code-review/`（Windows：`%USERPROFILE%\.agents\skills\security-code-review\`）。

**Codex 單一專案**：放到 `<專案>/.agents/skills/security-code-review/`。

**Claude Code**：使用 `~/.claude/skills/security-code-review/`，或專案的 `.claude/skills/security-code-review/`。

例如在 macOS／Linux／WSL 解壓下載的 ZIP 後：

```bash
mkdir -p "$HOME/.agents/skills"
cp -R security-code-review "$HOME/.agents/skills/security-code-review"
```

Windows PowerShell：

```powershell
New-Item -ItemType Directory -Force "$env:USERPROFILE\.agents\skills" | Out-Null
Copy-Item -Recurse -Force .\security-code-review "$env:USERPROFILE\.agents\skills\security-code-review"
```

從私有 GitHub 安裝時，可在已設定 SSH 權限的環境中將 `develop` 分支直接 Clone 到上述目錄。**需先將此 v2.1.2 套件提交到該分支**，否則遠端不會包含最新版功能。

## 混合來源編碼及完整檢核

來源程式碼可為 UTF-8、UTF-8-BOM、帶 BOM 的 UTF-16；遇到舊式編碼時預設依序嘗試 CP950、CP1252，並於報告驗證提出警告（此回退不代表百分之百辨識正確）。可在 Agent 內部呼叫時指定 `--source-encodings cp950,cp1252`，絕不修改受測程式碼。JSON／HTML 輸出仍統一 UTF-8。

`status=review` 代表「已執行審查但仍待外部證據」，不是尚未檢核。未完成或阻斷的項目需保留 `execution.state=pending/blocked`，並使正式報告驗證失敗；逐項完成後再產生 HTML。腳本只驗證審查資料，不會取代 Codex 的程式碼分析。

## Python 是否必要？

- Skill **辨識及 AI 閱讀程式碼不需要** Python。
- **目前的 HTML 產生、JSON／HTML 驗證需要 Python 3.10+** 與 `requirements.txt` 依賴。只需安裝一次，不用每次手動執行三個程式。

Codex 全域安裝範例（從任意目錄安裝依賴）：

```bash
python -m pip install -r "$HOME/.agents/skills/security-code-review/requirements.txt"
```

PowerShell：

```powershell
py -3 -m pip install -r "$env:USERPROFILE\.agents\skills\security-code-review\requirements.txt"
```

如公司限制全域安裝，請由系統管理者採公司核准的虛擬環境。依賴為 `jsonschema`、`referencing`、`PyYAML`。

## 為何從受測專案執行，而不是 Skill 目錄？

- **Skill 目錄只負責規則與工具**；Agent 讀取其中的 `SKILL.md`、規則、Schema 與 Python 程式。
- **受測專案是工作目錄**；原始碼搜尋、Git Revision、路徑與行號、報告輸出都相對受測專案。
- `complete_review.py` 只是 Agent 最後呼叫的整合流程，**不會單獨掃描原始碼**；`assessment.json` 必須先由 Agent 真正審查後建立。

在受測專案根目錄執行時，Agent 內部呼叫的指令概念如下（使用者通常不需要操作）：

```bash
python <SKILL_ROOT>/scripts/complete_review.py --target .
```

本程式會自動執行 `validate_assessment.py`、`generate_report.py`、`validate_report.py`，從受測專案的 `assessment_date` 決定 HTML 檔名，並開啟來源檔嚴格核對。

## 維護人員測試

在 Skill 根目錄執行（只供維護者驗收，不是一般使用流程）：

```bash
python scripts/validate_package.py
python -m unittest discover -s tests -v
```

主要檔案：`SKILL.md`、`rules/`、`schemas/`、`templates/security-report.html`、`scripts/complete_review.py`、`scripts/generate_report.py` 與 `scripts/validate_report.py`。

> 注意：檢核格式與來源檔案驗證通過，不等於資安問題已經過動態測試，亦不代表已取得法遵或公司資安簽核。
