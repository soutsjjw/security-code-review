# SKILL.md 建議增補段落（不覆蓋現有 SKILL.md）

請在原 `SKILL.md` 的第 9、10 項之後追加：

```markdown
## 報告生成（v2.1）
1. 先依原規則完成 `assessment.json`，以 `python scripts/validate_assessment.py reports/assessment.json` 驗證。
2. 依 `schemas/report.schema.json` 建立 `project.json` 與 `presentation.json`，不得複製其他系統資料。
3. 執行：
   `python scripts/generate_report.py --assessment reports/assessment.json --project reports/project.json --presentation reports/presentation.json --source-root <已審查原始碼根目錄> --strict-sources --save-report reports/report.json --output reports/CodeReview_YYYYMMDD.html`
4. 執行：
   `python scripts/validate_report.py --report reports/report.json --html reports/CodeReview_YYYYMMDD.html --source-root <已審查原始碼根目錄> --strict-sources`
5. 若未取得足夠資料填寫 `presentation`，應省略該欄位或清楚標示待確認，不得虛構 Before／After、修復期限及既有安全優點。
6. 僅驗證程式結束狀態為 0 時，才能標示為「報告資料與模板驗證通過」。這不等於漏洞已被驗證或公司資安核定。
```

`--strict-sources` 需要 Agent 可存取此次審查原始碼，且與 `assessment.git_revision` 對應；如果沒有來源檔請先保留 Review 並明確揭露限制。
