# Security Code Review — 跨系統資安審查 Skill（整合版 v2.1.1）

此套件將原有 **70 項資安檢核（規則集 `2.0.0-rc1`）** 與 **HTML 報告功能（Report Schema `2.1.0`）** 整合。適用於不同系統，不包含任何 EDS 實際審查結果。**公司資安正式核定仍待完成**。

> **重要：** 先前 `security-code-review-reporting-v2.1.0.zip` 僅包含報告功能增補檔案，未包含 `SKILL.md`，不能直接當完整 Skill 安裝。此整合版已具備 `SKILL.md`、70 項規則、模板、Schema 與程式。

## 1. 需要先安裝什麼？

| 使用目標 | 必要條件 |
| --- | --- |
| 讓 Codex / Claude Code 辨識 Skill | Codex / Claude Code、能存取的 `SKILL.md` 目錄；**不要求 Python** |
| 依規則進行 AI 靜態審查 | Agent 有權限讀取受測專案原始碼；不一定需要 Python |
| 執行目前的 `validate_*.py`、`generate_report.py` | **Python 3.10+** |
| 產出 EDS 風格 HTML、驗證 JSON、核對來源行號 | **Python 3.10+** 及 `requirements.txt` 依賴 |
| 開啟完成的 HTML | 瀏覽器；不需要 Python |

如無法安裝 Python，仍可使用純文字審查 Skill，但**無法使用這一版既有的 Python 報告產生與自動驗證程式**。未來若改寫成 Node.js 或單檔執行檔，才能免安裝 Python。

## 2. 安裝 Skill

此套件使用標準的 `SKILL.md` 目錄式 Skill，與 GitHub 插件／MCP 連線並非同一種安裝方式。安裝的重點是 **整個資料夾**，不能只複製 `SKILL.md`。

### A. Codex：所有專案共用（推薦）

macOS、Linux、WSL，在解壓縮 ZIP 的位置執行：

```bash
mkdir -p "$HOME/.agents/skills"
cp -R security-code-review-skill-v2.1.1 "$HOME/.agents/skills/security-code-review"
```

PowerShell：

```powershell
New-Item -ItemType Directory -Force "$env:USERPROFILE\.agents\skills" | Out-Null
Copy-Item -Recurse -Force .\security-code-review-skill-v2.1.1 "$env:USERPROFILE\.agents\skills\security-code-review"
```

確認檔案為：

```text
~/.agents/skills/security-code-review/
├── SKILL.md
├── rules/
├── schemas/
├── scripts/
├── templates/
└── requirements.txt
```

重新開啟 Codex 工作階段，要求：`使用 security-code-review Skill，對目前專案執行 70 項資安檢核。`

### B. Codex：只供單一專案使用

在**受測專案的根目錄**執行（macOS／Linux／WSL）：

```bash
mkdir -p .agents/skills
cp -R /path/to/security-code-review-skill-v2.1.1 .agents/skills/security-code-review
```

此模式會讓該專案共享 Skill；若需供多個系統使用，建議用 A 的個人共用安裝，或由公司統一部署。

### C. Claude Code

安裝在個人全域路徑（macOS／Linux／WSL）：

```bash
mkdir -p "$HOME/.claude/skills"
cp -R security-code-review-skill-v2.1.1 "$HOME/.claude/skills/security-code-review"
```

或複製到**受測專案**的 `.claude/skills/security-code-review/`。重新開啟 Claude Code，輸入 `/security-code-review` 啟動；若未顯示，請確認 `SKILL.md` 路徑與 Skill 名稱。

### D. 直接由 GitHub 私有儲存庫安裝

**前提：** 需先將本整合套件檔案合併並提交至 [GitHub `develop` 分支](https://github.com/soutsjjw/security-code-review/tree/develop)，否則目前 GitHub 的版本可能仍缺少報告產生器。

在已設定 GitHub SSH 權限的環境中：

```bash
mkdir -p "$HOME/.agents/skills"
git clone --branch develop --depth 1 \
  git@github.com:soutsjjw/security-code-review.git \
  "$HOME/.agents/skills/security-code-review"
```

此儲存庫根目錄本身已有 `SKILL.md`，因此可直接 clone 至 Skill 目錄，不要再多包一層無 `SKILL.md` 的資料夾。更新時在安裝目錄執行 `git pull --ff-only`。

## 3. 安裝 Python 與相依套件（需要產生 HTML 時）

確認版本：

```bash
python --version
```

請使用 Python **3.10 或以上**。在 Skill 目錄執行：

```bash
python -m pip install -r requirements.txt
python scripts/validate_package.py
python scripts/validate_assessment.py examples/assessment.example.json
```

若 Windows 無 `python` 指令，使用 `py -3` 代替，如 `py -3 -m pip install -r requirements.txt`。

建議於公司核准的虛擬環境安裝相依套件，避免影響其他專案。`requirements.txt` 包含 `jsonschema`、`referencing`、`PyYAML`，其中 `PyYAML` 是原有 `validate_package.py` 所需。

## 4. 執行 70 項檢核與產生 HTML

以下命令可從 Skill 目錄執行，請將 `/path/to/scanned-project` 改成**受測系統的真實原始碼根目錄**。

1. 由 Codex／Claude Code 依 `SKILL.md` 與專案內容建立 `reports/assessment.json`。不要把 `examples/*.json` 當作真實掃描結果。
2. 建立 `reports/project.json`，例如：

```json
{
  "name": "受測系統名稱",
  "language_framework": "ASP.NET Core"
}
```

3. 在 Skill 根目錄執行：

```bash
python scripts/validate_assessment.py reports/assessment.json
python scripts/generate_report.py \
  --assessment reports/assessment.json \
  --project reports/project.json \
  --source-root /path/to/scanned-project \
  --strict-sources \
  --save-report reports/report.json \
  --output reports/CodeReview_YYYYMMDD.html
python scripts/validate_report.py \
  --report reports/report.json \
  --html reports/CodeReview_YYYYMMDD.html \
  --source-root /path/to/scanned-project \
  --strict-sources
```

> 上述輸入路徑為**相對目前工作目錄**的示例，須先建立好對應 JSON；若從受測專案目錄執行，可改用 Skill 根目錄的 `scripts/` 絕對路徑。`presentation.json` 為選填，含改善優先順序、既有安全優點等資料；不應虛構。

### 只想測試 HTML 產生器

```bash
python scripts/generate_report.py \
  --report examples/demo-with-finding.report.json \
  --allow-demo \
  --output reports/demo.html
python scripts/validate_report.py --html reports/demo.html --allow-demo
```

此範例使用**虛構測試資料**，不是對任何真實系統完成掃描。

## 5. 驗收

```bash
python scripts/validate_package.py
python -m unittest discover -s tests -v
```

產出 HTML 後用瀏覽器開啟，確認 70 項結果、篩選、Before／After、RWD、深色模式與列印功能。

**限制：** 通過 JSON/HTML 的結構與來源驗證，並不等於資安漏洞真實性已由人工確認，也不代表公司政策或法規符合性已完成認證。

## 文件索引

- `SKILL.md`：Agent 檢核及報告產生流程。
- `docs/70-rules-standardized.md`：70 項規則。
- `schemas/assessment.schema.json`、`schemas/report.schema.json`：資料結構。
- `templates/security-report.html`：通用離線 HTML。
- `scripts/generate_report.py`：產生 HTML。
- `scripts/validate_report.py`：驗證 HTML。
- `docs/SKILL-integration.md`：從舊版升級提示。
