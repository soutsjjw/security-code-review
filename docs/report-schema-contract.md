# Report Schema v2.1.0 — 欄位與相容性

## 設計

`report.schema.json` 使用 JSON Schema Draft 2020-12，並透過相對 `$ref: "assessment.schema.json"` 引用規則集 2.0.0-rc1 的審查結果 Schema；避免讓報告專用欄位污染核心審查紀錄。

```text
report.json
├── report_schema_version  # 固定 "2.1.0"
├── project                # 不同系統的標頭資訊
├── assessment             # 原本 70 項審查結果；ruleset_version = "2.0.0-rc1"
├── rules                  # 70 項規則顯示資訊（可用完整規則物件或最小投影）
└── presentation           # 僅報告呈現用途
```

## 各部分要求

| 部分 | 必要欄位 | 補充說明 |
| --- | --- | --- |
| `project` | `name` | 可選 `language_framework`、`security_level`、`personal_data`、`attributes`；所有值皆須由各專案提供，不能套用 EDS。 |
| `assessment` | 原有七項必要欄位 | 核心 `assessment.schema.json` 已增加各項檢核的必要 `execution` 欄位；Finding、證據及例外繼續保存於核心結構。 |
| `rules` | `id`、`title`、`category`（70 筆） | 必須涵蓋目前完整 70 個規則 ID，且每個只能出現一次；允許完整規則物件額外欄位。 |
| `presentation` | 物件可為 `{}` | 所有視覺欄位均可選；不得為了美觀捏造不存在的內容。 |

## presentation 可選欄位

| 欄位 | 型別 | 用途 |
| --- | --- | --- |
| `demo` | boolean | 必須明確區別示範與正式報告。 |
| `review_type`、`reviewer` | string | 報告副標題與審查人員。 |
| `standards` | string[] | 實際採用規範與版本。 |
| `overall_risk` | `{ level, summary }` | `level` 僅能為 `critical`／`high`／`medium`／`low`／`info`／`review`；須由審查確認，不能依弱點數自動推論。 |
| `priorities` | `{label, finding_ids, description?}[]` | 依核定的改善優先順序排列；不得憑空指定改善期限。 |
| `strengths` | string[] | 已取得可驗證證據的既有安全設計優點。 |
| `methods`、`limitations` | string[] | 實際審查方法及限制。 |
| `finding_details` | `{ [finding_id]: FindingDetail }` | 弱點的詳細描述、OWASP 類別、程式碼位置與 Before／After。 |
| `footer` | string | 可選報告聲明。 |

`FindingDetail` 支援 `owasp_category`、`description`、`risk`、`locations`、`before_code`、`after_code`；`locations` 每項為 `{path,line_start,line_end}`。

## 相容性、限制與安全

- **相容性變更**：`assessment.checks[]` 新增必要的 `execution`：`state`（pending/completed/blocked）、`methods`（檢查方法）、`summary`（逐項審查摘要）、可選 `inspected_paths`（實際查核檔案）。正式報告的 70 項皆須 completed，不能把未執行項目填為 review。
- Schema 驗證欄位結構；`validate_assessment.py` 和 `validate_report.py` 的正式模式會拒絕 pending／blocked 與重複佔位文字。既有缺少 execution 的評估資料必須重新實際檢核後補齊。
- 新 Schema 可阻擋：不完整的 70 項規則、重複規則 ID、錯誤分類、無證據 `pass`／`fail`、缺乏理由的 `na`、非法風險等級、錯誤的程式碼位置結構。
- **JSON Schema 無法單獨驗證**：Finding ID 是否真的出現在 `assessment.findings`；來源檔是否存在與行號是否合法；`line_end >= line_start`；修正程式碼是否正確；規則版本與現有規則檔內容是否一致；例外有無簽核。這些須由第三階段的程式驗證。
- 透過 Schema 驗證不代表完成程式碼安全審查，也不代表通過公司資安標準。
- `presentation.demo: true` 表示資料只供示範；正式報告應為 `false` 並有已確認的證據。
- HTML 使用 `<script type="application/json">` 注入資料時，**必須在產生器安全跳脫 `<`、`>`、`&`**；JSON Schema 不負責防止 HTML 注入。
- Schema 以 `assessment.schema.json` 相對參照，正式 Validator 要設定正確的 Registry／基底 URI；`tests/test_report_schema.py` 提供正確範例。

## 最小 JSON 形狀

```json
{
  "report_schema_version": "2.1.0",
  "project": {"name": "被審查系統名稱"},
  "assessment": {"ruleset_version":"2.0.0-rc1","project_id":"...","git_revision":"...","assessment_date":"...","scope":"...","checks":[],"findings":[]},
  "rules": [],
  "presentation": {}
}
```

> 上面僅供說明結構，`checks` 與 `rules` 的空陣列不符合正式 Schema；完整合格範例請見 `examples/report-data.example.json`。
