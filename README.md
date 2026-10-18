# Security Code Review — HTML 報告產生與驗證 v2.1.0

本套件可整合到 `soutsjjw/security-code-review` 的 `develop` 分支，接續既有 **70 項規則、v2.0.0-rc1 Assessment Schema、v2.1 HTML 模板與 Report Schema**。不變更任何原始規則或稽核結論。

## 檔案與來源

| 檔案 | 是否新增 | 用途 |
|---|---|---|
| `scripts/report_common.py` | 新增 | JSON Schema／70 項檢核／引用／來源／HTML 通用驗證 |
| `scripts/generate_report.py` | 新增 | 由 `report.json` 或 `assessment.json` 產出單檔 HTML |
| `scripts/validate_report.py` | 新增 | 驗證報告 JSON 與 HTML 是否一致 |
| `templates/security-report.html` | 前階段成果 | EDS 風格的通用 HTML 模板，未更改 |
| `schemas/report.schema.json` | 前階段成果 | 既有 v2.1.0 報告契約，未更改 |
| `schemas/assessment.schema.json` | 參考副本 | 原 v2.0.0-rc1 Schema，**請勿覆蓋 GitHub 原檔** |
| `rules.json` | 參考副本 | 原 v2.0.0-rc1 完整 70 項規則，**請勿覆蓋 GitHub 原檔** |
| `tests/test_report_pipeline.py` | 新增 | 含安全測試的端到端單元測試 |
| `tests/test_report_schema.py` | 前階段成果 | 原報告 Schema 契約測試 |
| `examples/report-data.example.json` | 前階段成果 | 全部 70 項 Review 的示範 JSON |
| `examples/demo-with-finding.*` | 新增測試資料 | 包含虛構弱點以驗證版面，**非正式掃描** |

> 整合到現有 GitHub 時，建議只複製 3 個 `scripts` 新檔與測試檔；若尚未上傳前兩階段成果，再一起複製 `templates/security-report.html` 和 `schemas/report.schema.json`。

## 環境

Python >=3.10；需安裝 `jsonschema`、`referencing`。

```bash
python -m pip install -r requirements.txt
```

## 使用方式

### A. 完整 report.json → HTML

```bash
python scripts/generate_report.py \
  --report reports/report.json \
  --source-root /path/to/scanned-project \
  --strict-sources \
  --output reports/CodeReview_YYYYMMDD.html

python scripts/validate_report.py \
  --report reports/report.json \
  --html reports/CodeReview_YYYYMMDD.html \
  --source-root /path/to/scanned-project \
  --strict-sources
```

### B. 現有 assessment.json → HTML

`project.json` 的內容必須為 `{"name":"系統名稱","language_framework":"..."}` 之類的 `project` 物件，**不是**整份 YAML project-profile。`presentation.json` 為 `presentation` 物件，可省略。

```bash
python scripts/generate_report.py \
  --assessment reports/assessment.json \
  --project reports/project.json \
  --presentation reports/presentation.json \
  --source-root /path/to/scanned-project \
  --strict-sources \
  --save-report reports/report.json \
  --output reports/CodeReview_YYYYMMDD.html
```

省略 `--source-root` 時仍可驗證 Schema、引用和報告結構，但**無法驗證實際來源檔與行號**，將顯示 WARN；正式審查建議提供 `--source-root --strict-sources`。

### C. 只驗證獨立 HTML

```bash
python scripts/validate_report.py --html reports/CodeReview_YYYYMMDD.html
```

## 示範（不代表任何系統安全性）

```bash
python scripts/generate_report.py \
  --report examples/demo-with-finding.report.json \
  --allow-demo \
  -o examples/demo-with-finding.html

python scripts/validate_report.py --html examples/demo-with-finding.html --allow-demo
```

帶有 `presentation.demo: true` 的資料，未指定 `--allow-demo` 會驗證失敗。示範中的缺失、程式碼、專案名稱均為虛構。

## 驗證規則與限制

**檢核內容**：

- JSON Schema Draft 2020-12（`report` `$ref` 既有 `assessment`）及格式；
- 完整且不重複的 70 項檢核、規則版本、規則名稱和分類；
- Pass／Fail 必備證據、不適用原因、證據來源欄位；
- 弱點與檢核編號、優先順序與弱點、顯示位置與 Finding 證據之交叉引用；
- 來源路徑不得逃出掃描根目錄（含 Symbolic Link）、來源檔存在與行號界限（嚴格模式）；
- 非遮蔽 Before 程式碼的文字是否存在於相關來源範圍（有提供 `--source-root` 時）；
- 避免 `</script>` 等不安全字串造成 HTML Script 注入；
- HTML 含一份 JSON、必要章節、靜態錨點，且只變更模板中的 JSON Script 區塊；
- HTML 內嵌資料與原始 report.json 一致，所有統計由瀏覽器從資料計算。

**尚不能自動證明**：AI 發現是否真實、部署端防護是否存在、程式碼語義是否正確、修正方案是否安全、來源檔是否確實屬於聲稱的 Git SHA。正式使用仍需保留執行記錄及人工複核。`--strict-sources` 只核對目前提供的目錄，**不會執行 Git 簽章或檢出歷史版本**。

程式完全離線執行、不呼叫外部 CDN 或 API。輸入資料可能包含敏感程式碼，請在公司授權環境存放與存取。

## 自動化測試

```bash
python -m unittest discover -s tests -v
```

與 Skill 接軌的更新方式請見 `docs/SKILL-integration.md`。
