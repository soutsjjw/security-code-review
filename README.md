# Security Code Review — 通用 HTML 模板 v2.1 (第一階段)

此套件僅完成 **(1) 建立通用 HTML 模板**，延續 `EDS_CodeReview_20261013.html` 的版面風格與功能。**不包含**正式的 JSON Schema 擴充、報告產生器、檔案／證據驗證器或任何真實資安掃描結論。

## 檔案

| 路徑 | 用途 |
| --- | --- |
| `templates/security-report.html` | 通用、單檔、離線可開啟的 HTML 模板；**不含特定系統資料** |
| `examples/security-report-preview.html` | 已注入**純演示**的 70 項結果，直接開啟可檢查版面與互動 |
| `examples/report-data.example.json` | 演示用的報告資料格式，不可作為正式審查證據 |
| `docs/data-contract.md` | 資料欄位、注入方式、與現行 assessment schema 的關係 |

## 相容內容

保留與 EDS HTML 對應的七個章節：
1. 基本資訊與摘要（資訊表、四狀態統計、弱點嚴重度統計、整體風險）
2. 發現摘要（弱點內部連結）
3. 優先改善項目排序
4. 既有優點
5. 詳細檢核結果（十類、70 項，可收合與狀態篩選）
6. 發現與改善建議（程式碼位置、Before/After、風險等級篩選）
7. 審查方法與限制

額外支援人工切換深色／淺色、系統深色模式、RWD、列印展開內容、無外部依賴及 DOM 安全渲染。

## 快速預覽

用瀏覽器開啟 `examples/security-report-preview.html`。

其中所有符合／不符合統計、弱點、檔案位置與程式碼都是**人工演示資料**，不代表 EDS 或其他系統的實際審查結果。頁面最上方顯示演示警示。

直接開啟 `templates/security-report.html` 則會看到「尚未注入報告資料」，這是正常行為。

## 後續接入現有 Skill

建議放入你的 `security-code-review` 儲存庫：

```text
templates/
  security-report.html
examples/
  security-report-preview.html
  report-data.example.json
```

本模板使用單一 `<script id="report-data" type="application/json">` 放置報告資料，提供固定的注入位置 `__REPORT_DATA_JSON__`；完整規格詳見 `docs/data-contract.md`。

後續實作第二階段 JSON Schema 時，可保留現有 `assessment.schema.json`，另定義 `report.schema.json` 描述模板用的 **report envelope**；第三階段再由 `generate_report.py` 將經驗證的審查結果與規則目錄組裝成報告，注入模板。

## 注意

- 模板不會自行判斷風險與檢核結果；統計數字從 `assessment.checks`、`assessment.findings` 計算。
- 未提供的安全優點、Before/After 或方法限制，頁面會明確顯示缺少資訊，不會自行編造。
- 70 項只是報告的規則數目；模板不能代替檢核引擎、證據驗證器與人工複核。
- 渲染程式必須正確跳脫嵌入 `<script type="application/json">` 的 JSON；詳見資料契約的安全注意事項。
