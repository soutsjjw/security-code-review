# Security Code Review — HTML 報告 JSON Schema v2.1.0（第二階段）

目的：替已完成的跨系統通用 HTML 模板建立正式的 **report envelope** JSON Schema，**不修改原有 70 項規則**，亦不改變 `assessment.schema.json`（2.0.0-rc1）的結構。

## 交付檔案

| 路徑 | 用途 | 與 develop 分支比較 |
| --- | --- | --- |
| `schemas/report.schema.json` | HTML 報告資料外層結構與額外呈現欄位 | 新增 |
| `schemas/assessment.schema.json` | 原有審查結果 Schema，作為 `$ref` 依賴 | **未變更（隨包附上以供離線測試）** |
| `examples/report-data.example.json` | 可通過 Schema 的 70 筆 Review 純格式範例 | 新增 |
| `tests/test_report_schema.py` | JSON Schema 契約正向／反向測試 | 新增 |
| `docs/report-schema-contract.md` | 欄位、相容性與尚待第三階段驗證的限制 | 新增 |

此套件中的範例**並非任何系統的資安掃描結果**；未提供真正的漏洞或改善證據。

## 整合方式

把新檔案分別放入 `security-code-review` 儲存庫同名路徑；原有 `schemas/assessment.schema.json` 不需要替換。

HTML 模板仍使用 `templates/security-report.html`，不需變更。它會忽略新的頂層 `report_schema_version`，而使用 `project`、`assessment`、`rules`、`presentation` 呈現。

## 測試

```bash
python -m pip install jsonschema referencing
python -m unittest discover -s tests -p 'test_report_schema.py' -v
```

## 仍待第三階段實作

- 根據實際 `assessment.json` 與 `rules.json` 建立報告資料。
- 執行 `validate_assessment.py`，再執行 report.schema.json 驗證。
- 驗證 `finding_ids`、`finding_details` 等交叉參照與程式碼證據真實性。
- 將 JSON 安全注入 HTML 模板並產生單一離線 HTML。
- 驗證統計、內部連結、報告內容與列印／篩選功能。
