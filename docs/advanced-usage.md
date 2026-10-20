# 進階使用與完整審查流程

此頁收錄 README 省略的進階操作。一般使用者只需在受測專案的 Codex 對話中輸入 `$security-code-review`（Claude Code 為 `/security-code-review`）。

## 受測路徑與執行位置

- `SKILL_ROOT`：Skill 安裝目錄，保存 `SKILL.md`、規則、Schema、報告模板及 Python 腳本。
- `TARGET_ROOT`：實際受測專案，Agent 在此讀取程式碼、Git 版本及設定；結果一律寫到 `TARGET_ROOT/reports/security-code-review/`。
- 使用者指定路徑時，可呼叫 `$security-code-review /path/to/project`；不指定時使用目前受測專案。
- 對話指令不是系統 Shell 指令；Agent 必須實際閱讀來源檔，Python 腳本只負責排程、資料驗證及報告生成。

## Codex 可選 `/goal` 完整審查指令

在支援 `/goal` 的 Codex 版本中，於**受測專案的對話**輸入：

```text
/goal 使用 $security-code-review Skill，完整執行目前專案的全部 70 項資安檢核。

完成條件：
1. 逐項實際審查全部 70 條規則，確認 execution.state 均為 completed，且所有應審查原始碼／設定檔均完成逐檔核對。
2. 載入既有 assessment.json，保留所有已發現弱點及證據。
3. 發現弱點時寫入 Finding，不修改原始碼、不要求先修復。
4. 缺少部署、政策或動態測試證據時，記錄已完成的靜態分析及待確認事項，繼續其他檢核。
5. 每批保存結果，自動繼續下一批，直到 70/70 且 source_coverage.missing_source_file_count=0。
6. 執行 complete_review.py，成功產生並驗證 HTML 與 JSON 報告。
7. 只有在真正無法繼續的執行錯誤或資源限制時才停止，並保留進度及說明原因。

在完成以上條件前，不得將部分檢核結果視為最終交付。
```

若環境不支援 `/goal`，正常使用 `$security-code-review` 即可。單次執行能否完整完成仍受 Agent 實際可用工具與資源限制影響。

## 70 項執行迴圈

Agent 以安裝目錄中的 Python 腳本進行排程（下列為 Agent 內部指令，非一般使用者必須手動執行的步驟）：

```bash
sh "<SKILL_ROOT>/scripts/run-python.sh" "<SKILL_ROOT>/scripts/review_queue.py" --target "<TARGET_ROOT>" --init --batch-size 10
```

Windows PowerShell 對應指令：

```powershell
& "<SKILL_ROOT>\scripts\run-python.cmd" "<SKILL_ROOT>\scripts\review_queue.py" --target "<TARGET_ROOT>" --init --batch-size 10
```

首次執行可先用 `sh "<SKILL_ROOT>/scripts/run-python.sh" --check`（Windows：`& "<SKILL_ROOT>\scripts\run-python.cmd" --check`）唯讀檢查 Python 3.10+ 和相依套件。啟動器會依序嘗試 `python`、`python3`、`py -3`；若不可用，保留既有進度並回報安裝指令，不自動安裝。

1. 若受測專案已存在 `assessment.json`，先讀取並保留原有 Finding、證據及完成進度；否則才建立 70 項待審查草稿。
2. 依 `next_checks` 清單逐條搜尋程式碼、追蹤呼叫鏈及組態，記錄真實檔案路徑、行號、方法、證據與理由。
3. 每項審查後記錄 `execution.state`（`pending`、`completed`、`blocked`）以及 `status`（`pass`、`fail`、`review`、`na`）；**不能因待辦清單列出某規則就當作完成**。
4. 每批保存 `assessment.json` 並重新取得下一批；只有全部 70 項 `completed`，且 `source_coverage.missing_source_file_count=0` 才生成最終報告。
5. 真的無法繼續時保留所有進度與實際錯誤，不得把部分結果當成最終交付。

若已完成來源靜態分析但沒有部署／政策／人工／動態佐證，使用 `status=review` 並明列缺口，允許 `execution.state=completed`。尚未執行的規則不可標記為 `review` 或 `completed`。

找到弱點時以真實證據建立 Finding，保留風險、影響及改善建議，繼續其餘審查；**本 Skill 不修改受測原始碼，亦不要求先修復才能產生報告**。

完成後，Agent 在受測專案執行：

```bash
sh "<SKILL_ROOT>/scripts/run-python.sh" "<SKILL_ROOT>/scripts/complete_review.py" --target "<TARGET_ROOT>"
```

Windows PowerShell：
```powershell
& "<SKILL_ROOT>\scripts\run-python.cmd" "<SKILL_ROOT>\scripts\complete_review.py" --target "<TARGET_ROOT>"
```

此流程會依序呼叫 `validate_assessment.py`、`generate_report.py`、`validate_report.py`，於受測專案生成 `report.json` 與 `CodeReview_YYYYMMDD.html`，並檢查來源檔案、行號與資料結構。產出日期依 `assessment_date` 決定。

## 舊版規則集相容性

- 核心規則集正式版本為 **`2.0.0`**；新增的 `assessment.json` 將使用新版本號。
- 舊專案已存在的 `2.0.0-rc1` `assessment.json` 可沿用，**不清空 70 項進度及 Findings**。報告驗證會顯示舊版資料提示。
- 版本升級不代表舊審查已實際涵蓋後來新增的 TACERT、OWASP 2025、V1.3、V3.2 主文及附件；需依原始證據補查。
- 其餘版本或規則 ID 不一致仍拒絕驗證。無須變更舊檔的 Findings 或將 `completed` 歸零。

## 法定責任等級與系統防護需求分級

**資通安全責任等級 A～E** 與 **個別系統的防護需求等級 普／中／高** 是兩組不同的法規概念，不能相互推算。

Agent 於來源檢查時可依現有證據提出 A～E 初步研判並記錄 `project.security_level_assessment`；無足夠業務或制度資料就標示「待確認」。**正式核定結果**才使用 `project.security_level` 與 `security_level_basis`，不可用缺少漏洞或只看單一程式碼功能推定法定等級。

若有正式系統防護需求分級證據，於受測專案 `project.json` 記錄：

```json
{
  "name": "受測系統",
  "protection_demand_level": "中",
  "protection_demand_level_basis": "示例：可追溯的系統防護需求分級紀錄"
}
```

沒有正式依據時不填，並讓 V1.3 80 項及 V3.2 附件 1 的適用性保持「分級待確認」，不會阻斷原 70 項的程式碼審查。

## 可選的獨立查檢證據

以下 JSON 檔案位於 `reports/security-code-review/`，只需在**有實際可核對證據**時建立：

| 檔案 | 範圍 | 未提供時 |
|---|---|---|
| `baseline_assessment.json` | V1.3 80 項防護基準 | 依分級列待確認／未評估 |
| `web_appendix1_assessment.json` | V3.2 附件1 55 項 | 依分級列待確認／未評估 |
| `web_appendix3_assessment.json` | 附件3 六項 HTTP 標頭 | 六項皆 `not_assessed` |

人工查證原則：狀態 `pass/fail/review/na` 需要審核者、日期及理由；`pass/fail` 另需實際證據參照。附件3 的 `pass` 還須有經核實的 HTTPS 回應證據及環境，不能只看 `web.config` 或 Middleware 設定。證據欄位存在不保證外部工件真實性，應由審核者確認。

V3.2 限用 ASP.NET/.NET、IIS 與通用 Web 安全控制，**排除 Java 與 PHP 專屬實作**。附件3 的 CSP `unsafe-inline`、`unsafe-eval` 示範不是安全預設；亦需評估 HSTS preload 與 Permissions-Policy 的實際語法和瀏覽器支援。

## 審查範圍與檔案數

`assessment.scope` 是描述文字。實際審查檔案必須由每條已完成規則的 `execution.inspected_paths` 提供，不能把檔名搜尋或專案盤點結果當作已審查。

`review_queue.py` 會計算完整來源檔覆蓋，列出 `source_coverage`（應審查、已審查與缺漏數量、缺漏副檔名分布），並以 `next_source_paths`（每批最多 30 個）列出待逐檔閱讀的來源。即使 70 項規則顯示 `completed`，仍缺任一來源檔也不會設定 `ready_for_report=true`；`complete_review.py` 與正式來源驗證也會阻止輸出。

例如指定目錄共有 660 個 `.cs`，只有 13 個有真實已完成的 `inspected_paths` 紀錄，應顯示剩餘 647 個待審查，不能聲稱 70/70 已完整審查。所有源碼、.NET 頁面與相關專案設定應逐檔閱讀，對照實際關聯規則及必要證據，必要時重新審查已 completed 的規則。

可使用 `assessment.scope_details.projects` 記錄專案名稱與路徑，以及 `excluded_paths` 記錄排除路徑與原因。報告依實際路徑去重統計專案數、檔案數、盤點及排除資訊，不能手動造數字。

## 編碼與來源核對

來源檔支援 UTF-8、UTF-8-BOM、帶 BOM UTF-16；必要時唯讀回退 CP950、CP1252，並保留可能誤判的警告。JSON/HTML 輸出維持 UTF-8，**不修改受測原始檔**。

若需要檢查指定行號，Agent 可呼叫：

```bash
sh "<SKILL_ROOT>/scripts/run-python.sh" "<SKILL_ROOT>/scripts/source_reader.py" --source-root "<TARGET_ROOT>" --path "src/IdentityService.cs" --start 1 --end 200
```

## 維護與驗證

Python 3.10+；在 Skill 根目錄安裝 `requirements.txt` 後：

```bash
python scripts/validate_package.py
python -m unittest discover -s tests -v
```

核心檔案包括 `rules.json`、`rules.yaml`、`rules/`、`schemas/`、`templates/security-report.html` 及 `scripts/`。規則集 v2.0.0 的正式發布**不需公司資安簽核**；個別專案的實際法規適用、風險接受與制度文件，仍須依其權責與證據確認。
