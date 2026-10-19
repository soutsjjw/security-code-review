# Report Schema v2.1.0 — 欄位與相容性

## 設計

`report.schema.json` 使用 JSON Schema Draft 2020-12，並透過相對 `$ref: "assessment.schema.json"` 引用規則集 2.0.0-rc1 的審查結果 Schema；避免讓報告專用欄位污染核心審查紀錄。

```text
report.json
├── report_schema_version  # 固定 "2.1.0"
├── project                # 不同系統的標頭資訊
├── scope_inventory        # 自動盤點與完成審查的逐檔紀錄（提供 source-root 時）
├── assessment             # 原本 70 項審查結果；ruleset_version = "2.0.0-rc1"
├── rules                  # 70 項規則顯示資訊（可用完整規則物件或最小投影）
└── presentation           # 僅報告呈現用途
```

## 各部分要求

| 部分 | 必要欄位 | 補充說明 |
| --- | --- | --- |
| `project` | `name` | 可選 `language_framework`、`security_level`、`security_level_basis`、`security_level_assessment`、`personal_data`、`attributes`；`security_level` 僅允許 A～E／待確認／不適用，A～E 必須附分級依據。 |
| `assessment` | 原有七項必要欄位 | 核心 `assessment.schema.json` 已增加各項檢核的必要 `execution` 欄位；Finding、證據及例外繼續保存於核心結構。 |
| `rules` | `id`、`title`、`category`（70 筆） | 必須涵蓋目前完整 70 個規則 ID，且每個只能出現一次；允許完整規則物件額外欄位。 |
| `presentation` | 物件可為 `{}` | 所有視覺欄位均可選；不得為了美觀捏造不存在的內容。 |

## 機關資通安全責任等級

- 依《資通安全責任等級分級辦法》（115 年 1 月 7 日修正）第 2 至 10 條，機關依業務與維運責任區分 A～E 級；同時符合多個等級者依第 9 條以最高等級為原則，實際核定／調整程序依第 3、10 條辦理。
- 執行 70 項審查時自動初判：Agent 檢查已讀取的程式碼、設定、權限控管及業務文件，寫入 `project.security_level_assessment`；缺少資料時記錄未能判定原因，不中斷審查。若 Agent 未填，`scripts/security_level.py` 依 completed 的 `inspected_paths` 自動擷取明確的角色／權限程式碼作 C 級技術線索；無證據顯示待確認，不以 absence 推定 D／E 級。
- `security_level_assessment` 格式：`{status: "preliminary"|"undetermined", level:"A"|"B"|"C"|"D"|"E"|"待確認", basis:string, evidence:[{path,line_start,line_end}], missing_information:string[]}`。preliminary 必須有已完成審查的真實來源檔與行號；初判不代表法定核定，且不能排除較高級別。
- `project.security_level` 僅代表**已取得正式認定／核定的機關等級**；無可核對資料時填「待確認」或省略，不適用對象填「不適用」。正式核定優先於初判顯示。
- 指定 A～E 級時須填 `project.security_level_basis`（認定／核定佐證）；資通系統防護需求分級（第 11 條及附表九）及程式碼整體風險 `presentation.overall_risk` 應分別判斷。
- 法規：https://law.moj.gov.tw/LawClass/LawAll.aspx?pcode=A0030304

## 審查範圍與相容性

- `assessment.scope` 仍是文字描述。新增可選 `scope_details.projects=[{name,path}]` 與 `scope_details.excluded_paths=[{path,reason}]`（皆相對受測根目錄）；沒有專案對照不得自動假設為 1 個專案。
- `execution.inspected_paths` 只填入各 completed 規則確實讀取核對的檔案。盤點到的檔案不等於已檢查。
- `scope_inventory` 是工具生成的選用報告欄位：`inventory_file_count`、`eligible_file_count`、`excluded_file_count`、`reviewed_file_count`（跨規則去重）、`reviewed_files`（每檔關聯規則）、`file_types`、`projects`、`excluded_paths`、`declared_project_count`、`reviewed_project_count`。
- `reviewed_project_count` 只計算明確宣告且至少有一個已審查檔案的專案；未提供對照為 `null`。未有任何逐檔紀錄則記 0 並警告，不能宣稱全案已審查。
- 盤點統計反映報告產生時工作目錄的一般檔案，不追蹤 symlink，不代表 Git Revision 對應的歷史版本。舊版不含 `scope_inventory` 仍能載入。

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
