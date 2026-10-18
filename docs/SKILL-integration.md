# Skill 呼叫與報告流程（v2.1.2）

本套件已整合 `SKILL.md`，不需再手動追加指令。

在受測專案開啟 Codex，輸入 `$security-code-review`（或 `$security-code-review <專案路徑或檢核範圍>`）。Claude Code 使用 `/security-code-review`。

Agent 將在受測專案的 `reports/security-code-review/` 建立本次檢核 JSON、專案資訊與選填的呈現資料；再從該專案的根目錄執行：

```bash
python <SKILL_ROOT>/scripts/complete_review.py --target <TARGET_ROOT>
```

此 Python 程式只整合 JSON 驗證、報告渲染、HTML 驗證，不會自行做原始碼資安掃描。來源檔路徑相對於 `TARGET_ROOT`，而規則與工具檔路徑相對於 `SKILL_ROOT`。

產出：`reports/security-code-review/CodeReview_YYYYMMDD.html`、`report.json`。

若 Python、依賴套件或足夠審查證據不存在，Agent 須揭露未完成項目，不得回報驗證通過。
