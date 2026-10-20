# 通用 HTML 模板資料契約

這份契約是為 HTML 顯示層設計的 **report envelope**，不會覆寫或自行修改 `schemas/assessment.schema.json`。正式 Schema 與報告產生器分別為 `schemas/report.schema.json`、`scripts/generate_report.py`。

## 最上層

```json
{
  "project": {
    "name": "系統名稱",
    "language_framework": "主要語言與框架",
    "security_level": "待確認",
    "personal_data": "是／否／待確認"
  },
  "assessment": {
    "ruleset_version": "2.0.0",
    "project_id": "SYSTEM-01",
    "git_revision": "實際 Git SHA",
    "assessment_date": "YYYY-MM-DD",
    "scope": "審查範圍",
    "checks": [],
    "findings": []
  },
  "rules": [],
  "presentation": {}
}
```

**assessment**：以正式規則集 v2.0.0 建立；相容舊版 2.0.0-rc1 的既有紀錄（保留 Findings 和進度；新規範仍需實際補查）。目前 v2.0.0 審查結果欄位，不自行在其中添加原 Schema 不允許的欄位。其 70 筆 `checks` 應已通過原專案 `scripts/validate_assessment.py`。

**rules**：來自相同規則版本的 `rules.json` 的 `rules` 陣列，可以是完整規則，顯示至少使用 `id`、`title`、`category`、`origin.legacy_levels`。務必與此次評估使用的規則版本一致，不要混入其他專案的檢核結果。

**project**：每個專案自己的報告標頭資訊。依《資通安全責任等級分級辦法》（115 年 1 月 7 日修正）第 2 至 10 條，`security_level` 只表示**機關資通安全責任等級**，可填 `A`／`B`／`C`／`D`／`E`／`待確認`／`不適用`。未提供時報告顯示「待確認」；填 A～E 級須提供非空白的 `security_level_basis`（權責單位分級認定或核定的日期、文號或其他可核對依據）。不得由原始碼弱點數量自行推定等級。與系統防護需求分級（第 11 條／附表九）和 `presentation.overall_risk` 不同。法規：https://law.moj.gov.tw/LawClass/LawAll.aspx?pcode=A0030304

**security_level_assessment**：由 Agent 隨 70 項實際審查自動初判，或由報告產生器從 completed 的 inspected_paths 擷取角色／權限程式碼作第 6 條 C 級技術線索。格式為 `{status,level,basis,evidence:[{path,line_start,line_end}],missing_information:[string]}`；無法判定時存「待確認」與原因，不中斷審查，亦不得寫成已核定的 `security_level`。

**presentation**：HTML 顯示所需的額外資料；無資料時顯示明確提示。

## presentation 選填欄位

| 欄位 | 型別 | 用途 |
| --- | --- | --- |
| `review_type` | 字串 | 報告副標題，例如 AI 輔助靜態審查 |
| `reviewer` | 字串 | 審查者／使用之 AI Agent |
| `standards` | 字串陣列 | 實際採用的標準版本 |
| `overall_risk` | `{level,summary}` | 審查員確認的整體風險（`critical/high/medium/low/info/review`），不自動從缺失數量推斷 |
| `priorities` | 物件陣列 | `{label,finding_ids,description}`；省略時依風險等級分組，不推定改善期限 |
| `strengths` | 字串陣列 | 經證據支持的既有優點 |
| `methods` | 字串陣列 | 本次實際執行方法 |
| `limitations` | 字串陣列 | 未執行的測試、外部佐證限制等 |
| `finding_details` | 物件 | 以 Finding ID 為鍵，對應下表的細節 |
| `footer` | 字串 | 自訂報告頁尾聲明 |
| `demo` | 布林值 | 僅供示範頁使用，真實報告必須為 `false` 或省略 |

`finding_details` 範例：

```json
{
  "F-01": {
    "owasp_category": "A01:2025",
    "description": "經驗證的問題描述",
    "risk": "可利用條件與實際影響",
    "locations": [{"path": "src/Example.cs", "line_start": 10, "line_end": 22}],
    "before_code": "// 原始碼摘錄（已遮蔽機敏資訊）",
    "after_code": "// 建議修改（須經人工複核）"
  }
}
```

如果沒有提供 `locations`，模板會從 `assessment.findings[].evidence` 的 `kind=source` 來源證據取用 `path`、`line_start`、`line_end`。

`before_code` 和 `after_code` **只可使用真實佐證與經檢查的修正建議**；缺值時模板會顯示「未提供」，不會自行填充假程式碼。

## 安全注入規則

`templates/security-report.html` 具有：

```html
<script id="report-data" type="application/json">__REPORT_DATA_JSON__</script>
```

請讓未來的 Generator **只替換這個元素的文字內容**，不能全域取代 `__REPORT_DATA_JSON__`，因為 JavaScript 會以此字串偵測尚未注入的模板。

序列化 JSON 後，須在放入 HTML 前處理 HTML script 特殊字元。例如 Python 可使用：

```python
safe_json = json.dumps(report, ensure_ascii=False).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
```

此處程式碼中的 `\\u003c` 表示輸出的 JSON 必須包含實際的六個字元 `\u003c`，以防資料中的 `</script>` 意外結束 script 區塊並造成 HTML 注入。

HTML 模板使用 `textContent`、`createElement` 建立頁面，避免將來自審查資料的內容直接放進 `innerHTML`。

正式 Generator 須另外執行 JSON Schema、來源行號、統計與報告完整性驗證。**本交付物尚未實作該 Generator。**


## 逐項檢核執行紀錄（v2.1.3）

每筆 `checks[]` 新增必要 `execution`，例如：

```json
{"state":"completed","methods":["source_review","configuration_review"],"summary":"已查閱登入授權流程及相關組態；缺少部署環境資訊尚待確認","inspected_paths":["src/Auth/AccessPolicy.cs"]}
```

`execution.state` 可為 `pending`、`completed` 或 `blocked`；正式報告要求全部 completed。`status=review` 可搭配 completed，意指完成可執行的查核而仍缺外部證據。欄位自填不能作為實際執行的獨立證明。
