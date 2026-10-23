# 進階使用與完整審查流程

此頁收錄 README 省略的進階操作。一般使用者只需在受測專案的 Codex 對話中輸入 `$security-code-review`（Claude Code 為 `/security-code-review`）。

## 受測路徑與執行位置

- `SKILL_ROOT`：Skill 安裝目錄，保存 `SKILL.md`、規則、Schema、報告模板及 Python 腳本。
- `TARGET_ROOT`：實際受測專案，Agent 在此讀取程式碼、Git 版本及設定；結果一律寫到 `TARGET_ROOT/reports/security-code-review/`。
- 使用者指定路徑時，可呼叫 `$security-code-review /path/to/project`；不指定時使用目前受測專案。
- 對話指令不是系統 Shell 指令；Agent 必須實際閱讀來源檔，Python 腳本只負責排程、資料驗證及報告生成。

## .NET 專用分析器（未來擴充 .NET Framework／Vue）

本階段 `scripts/analysis_adapters.py` 僅啟用 `dotnet-modern` Adapter。傳統 .NET Framework、Vue 及混合專案目前會拒絕完整審查，而非默默跳過；未來可增加 Adapter，而不改動共用的 70 條規則、逐檔證據契約或報告格式。

Agent 在開始佇列之前先執行下列**結構索引準備**（初次 full，重跑可改 incremental）：

```bash
sh "<SKILL_ROOT>/scripts/run-python.sh" "<SKILL_ROOT>/scripts/analysis_prepare.py" --target "<TARGET_ROOT>" --mode full
```

Windows PowerShell：

```powershell
& "<SKILL_ROOT>\\scripts\\run-python.cmd" "<SKILL_ROOT>\\scripts\\analysis_prepare.py" --target "<TARGET_ROOT>" --mode full
```

新增第二層審查證據閘門：`file_reviews[].rule_reviews` 與 `checks[].evidence` 每筆來源證據都必須引用實際相關的控制邏輯；不得以方法宣告、`using`、欄位、泛用設定，或跨檔共用的排除理由來湊數。當 70/70 completed 仍未通過，`review_queue.py --compact` 會顯示 `recheck_rule_ids` 和需重新驗證的 `next_checks`。這些是補查工作，不改寫 Findings。

Roslyn 索引保留型別、方法起訖行、呼叫所在方法、接收者型別及合成編譯得到的符號／介面實作候選；`cross_file_call_hints` 記錄不截斷的跨檔候選與呼叫點 ID。`semantic_*` 仍不等於真正專案建置／執行期目標，`receiver_type_candidate` 和 `name_only_ambiguous` 亦須人工核對。新索引下須依 [P1 結案協定](p0-review-guards.md#p1跨檔呼叫點必須人工結案) 完成 `callsite_reviews`；未解歧義不得將跨檔規則標為 completed。與 CodeGraph 不可用時一樣回退為人工查核，不能假裝已追蹤資料流。

這一步也會將每個來源檔的多條高辨識度規則候選存到 `analysis/structure-index.json` 的 `rule_candidates`，並回傳候選檔案與關聯數。增量模式只會在來源 SHA256 未變、候選分析器版本相同時重用候選；候選只供定位，不會寫入 pass/fail/completed。`review_queue.py` 的 `next_source_candidates` 顯示下一批缺少有效逐檔審查紀錄的檔案及其候選規則。

這一步偵測 CodeGraph 與 .NET SDK 8+ 的 Roslyn。CodeGraph 須先由使用者在受測專案執行 `codegraph init`；缺少 CodeGraph／SDK 時只退回既有搜尋與人工分析，**不得視為已執行 Roslyn 或完整 SAST**。Roslyn 只提供 C# syntax tree 的 types、methods 與 invocation 候選（非跨方法污點證明）；Agent 仍要核對程式碼及配置。增量快取只共用相同 SHA256 與相同分析器版本的結構資料，不沿用過期安全結論。

Token 優化佇列：

```bash
python "<SKILL_ROOT>/scripts/review_queue.py" --target "<TARGET_ROOT>" --init --batch-size 10 --compact
python "<SKILL_ROOT>/scripts/review_queue.py" --target "<TARGET_ROOT>" --detail-id CR-05
```

對應來源可額外查詢保守的 .NET 安全規則候選（僅線索，並非資安結論）：

```bash
python "<SKILL_ROOT>/scripts/analysis_candidates.py" --source-root "<TARGET_ROOT>" --path "src/Web/Controllers/AccountController.cs"
```

若出現 `AC-04`、`IN-03`、`AU-09` 等候選，必須核對實作、呼叫端和資料流，將所有真正適用的規則建立多對多 `file_reviews[].rule_reviews`／`checks[].execution.inspected_paths` 關聯；不適用時可使用 `candidate_exclusions` 按規則記錄至少 40 字的具體理由。不可讓候選工具自行完成檢核。只有 `using`、註解、方法宣告的來源不算完成證據。缺外部佐證的 `review` 應指定缺少的工件和查核範圍，不得套用部署／政策／動態測試通用清單。

精簡佇列只列待辦及搜尋候選，逐條檢核前以 `--detail-id` 取得所有標準對照。其餘逐檔 10 類篩選、70 項完成證據、Finding 與原有報告驗證均**不可略過**。

執行器若提供實際 Token 數，可選擇寫入統計：

```bash
python "<SKILL_ROOT>/scripts/token_metrics.py" --target "<TARGET_ROOT>" --executor "Codex CLI" --run-id "review-001" --input-tokens 100 --output-tokens 50 --cached-input-tokens 10 --tool-calls 3
```

數字必須是實際 API／執行器回傳資料，上述僅示範命令格式。統計位於 `reports/security-code-review/analysis/token-usage.jsonl`，不包含程式碼或推論出的 Token 值。

## 單代理 P0 完整性檢查（不含子代理）

執行 `analysis_prepare.py` 後，先以 `review_safety.py --target "<TARGET_ROOT>" --plan` 取得 70 項的最小責任範圍及需追查的來源／關聯候選。每檔依序完整篩選全部規則；`cross_file` 和 `project` 類別須補足結案證據。透過 `--stage <JSON路徑>`、`--integrate` 進行工作中結果的獨立暫存與有衝突檢查的整合，並以 `--validate` 確認結案及工作樹版本；正式結果仍維持原有 assessment Schema。

新機制拒絕來源快照異動與混合 Git Revision，並要求跨檔結案及全專案責任確認。若原始碼真的異動，須先調查、明確 `--snapshot-refresh` 並重新執行 `analysis_prepare.py`，再重新覆核全部無法證明未受影響的安全結論；既有 Findings 與歷史證據保留。不要把索引候選當作已完成的呼叫鏈，也不能複製制式結案文字。

詳細 JSON 實例、參數、版本限制與不支援的語意分析類型見 [六項 P0 守門指引](p0-review-guards.md)。

## Codex 可選 `/goal` 完整審查指令

在支援 `/goal` 的 Codex 版本中，於**受測專案的對話**輸入。以下使用可攜的 Skill 名稱 `$security-code-review`，不綁定個人電腦的安裝路徑：

```text
/goal 使用 $security-code-review Skill，對目前專案執行完整、具備真實程式碼證據的 70 項資安檢核。

前置：

- 使用目前已包含「review 判定規則收斂」的 SKILL.md（原 claude/tighten-review-decision-rules 分支內容已整合時，以安裝版本為準）。判定一律遵循其中「共同證據與結果判定」的判定階梯；如果目前安裝的 SKILL.md 缺少該段，先回報版本不一致，不得沿用舊判定規則完成報告。
- 於 Agent 實際執行環境先執行 python --version，確認 Python 3.10+（原測試環境曾回傳 3.13.14，不代表所有環境皆相同）。若 python 不可用，改試 python3、py -3，並使用 Skill 的 run-python.sh／run-python.cmd --check 驗證相依套件；仍失敗時依沙箱權限要求處理，不得擅自繞過執行限制，保留進度並回報真正阻斷原因。
- 維持單代理執行，不啟動子代理或平行審查；保留六項 P0 完整性守門。

完成條件：

0. 先執行 analysis_prepare.py，確認全部受測專案均為 .NET Core／現代 .NET；偵測並優先使用可用的 CodeGraph 與 Roslyn。利用既有結構快取減少重複讀取，失敗則回退，但不得把索引當成資安判斷。使用 review_queue.py --compact 取得待辦，每條規則透過 --detail-id 取完整要求並載入實際對應的標準文件。增量只重用結構證據；來源有變更時，依版本快照及可信影響閉包重新查核，不能沿用未重新驗證的安全結論。
   - 執行 review_safety.py --plan，確認全部 70 項的 local／cross_file／project 責任範圍；跨檔關聯候選（DI、Middleware、設定、Endpoint、跨專案引用）必須實際追查。來源快照與結構索引不一致時先排除異動原因，不得混用版本。

1. 完整盤點受測專案的原始碼、設定檔、專案檔、相依套件及相關 CI/CD 設定，建立實際審查範圍。全專案規則即使沒有關鍵字命中，也必須確認控制責任與缺席情況。

2. 逐檔實際閱讀程式碼，依 rules.json 的全部 70 條規則判斷適用性：
   - 不得只依檔名、關鍵字或 Regex 判定完成。
   - 不得只取第一個命中的檢核項目。
   - 不得預設使用 XX-01 或 SI-01。
   - 追蹤適用的程式碼、呼叫鏈、資料流及設定。
   - 一個檔案可關聯多條適用規則，但不得為增加數量而建立無依據的關聯。
   - 每個檔案完成十類適用性篩選；無直接適用項目仍須提出已核對的控制責任及理由，不得制式填入「無直接適用」。

3. 對每項適用規則實際執行靜態安全分析：
   - 驗證安全控制的實作及有效性。
   - 檢查可能的攻擊路徑、繞過條件與弱點。
   - 記錄具體來源路徑、行號、檢查內容、證據及判定理由。
   - 搜尋或關鍵字命中只能作為分析線索，不能視為已完成檢核。
   - 追查跨檔／全專案規則的必要控制鏈、組態覆寫及責任元件；補查任務未完成時，不得提前標記 completed。

4. 依實際證據判定結果（遵循 SKILL.md「判定階梯」，先判斷可證實的缺陷）：
   - pass：控制已由實際控制邏輯、設定與呼叫鏈證實有效，且符合該規則 pass_condition。
   - fail：來源、設定或呼叫鏈已證實缺陷、規則間矛盾、不安全預設值，或儲存庫中應有的控制不存在（須記錄搜尋範圍及責任分析）；建立 Finding。
   - review：僅限部署拓撲、營運與制度紀錄、儲存庫外平台設定、manual_boundary 確實阻斷結論的事項，或已嘗試執行但因環境失敗而無法取得的必要掃描結果。decision_reason 須先寫程式碼已判定的部分，再以「待確認：」指名具體工件與缺口，並依規定填寫 review_kind。
   - na：有具體證據及理由確認不適用，且已核對控制責任歸屬。
   - 下列情形不得標 review：缺測試（含重放、邊界、整合、授權測試）；缺角色或 ownership 矩陣（須自行讀碼建立）；自承尚未完成的資料流或 Handler 盤點；decision_reason 已寫出缺陷或矛盾。
   - 靜態控制成立但缺測試／文件時，依控制實際情形判 pass 或 fail，於 decision_reason 說明缺口；不得因此 review。
   - 標記 review 前須通過 SKILL.md 的三題自檢。review 比例超過 40% 須逐條重審，不能以比例機械改判。
   - 不得預設所有檢核為 review，也不得僅因未執行動態測試就把靜態可判定項目設為 review。

5. 保留既有 assessment.json、file_reviews、Findings 及所有證據。
   - 對缺乏實質分析的既有 completed 紀錄重新查核。
   - 既有 status=review 的項目，一律依新版判定階梯重新判定；能改為 pass 或 fail 者須更新 status、decision_reason 與必要 Finding，保留原有證據，不得刪除。
   - 不得使用固定模板、批次填入理由或製造檢核結果。
   - 不得修改受測專案原始碼，也不要求先修復弱點。
   - 工作中結果使用 review_safety.py --stage 獨立暫存，再以 --integrate 檢查衝突後整合。覆核既有 completed 須有真實重新審查證據及必要的修訂流程，不得覆寫已確認弱點。

6. 每批保存真實審查結果，持續執行直到：
   - 70 項規則均已實際完成。
   - source_coverage.missing_source_file_count = 0。
   - review_integrity_errors 與 rule_integrity_errors 均為空。
   - assessment.file_reviews 與 execution.inspected_paths 一致。
   - review_safety.py --validate 通過，safety_integrity_errors 為空。
   - 跨檔／全專案規則的結案紀錄完整，沒有未追查或未排除的關聯候選與 open_issues。
   - Git Revision、來源 SHA256 與分析索引一致；來源異動後須依 snapshot-refresh 與重查機制處理，不能直接沿用舊 completed。
   - review_queue.py 回傳 ready_for_report=true。
   - 所有完成判定均有足夠的真實檢核依據。

7. 正式交付前再次檢查：
   - 是否存在大量無差別 review。
   - 是否存在大量複製的檢核理由或摘要。
   - 是否存在只有關鍵字分類、沒有實質分析的紀錄。
   - 是否有已知弱點未建立 Finding。
   - 是否有已標記 completed 但沒有足夠查核證據的規則。
   - 是否有 decision_reason 同時描述缺陷或矛盾卻標為 review。
   - 是否有 review 理由只是「缺測試」或「缺矩陣」。
   - 是否有 review 未以「待確認：」指名具體工件。
   - 是否有全專案控制缺席、版本不一致、跨檔證據或 Finding 衝突仍未處理。
   發現上述問題時，必須重新執行相關檢核，不得只修改 JSON 以通過驗證。

8. 完成後執行 complete_review.py，成功產生並驗證 HTML 與 JSON 報告。報告必須能追溯檔案、適用規則、證據與檢核結論，並維持相關規範及附件的獨立查證要求。

9. 只有真正無法繼續的執行錯誤或資源限制才能停止。停止時保留既有進度及 Findings，明確列出尚未完成的工作，不得宣稱已完成全部審查。

在所有條件真正完成前，不得以 70/70 completed、100% 檔案覆蓋率或 JSON Schema 驗證通過，直接宣稱已完成實質資安審查。
```

若環境不支援 `/goal`，正常使用 `$security-code-review` 即可。單次執行能否完整完成仍受 Agent 實際可用工具與資源限制影響。

## 70 項執行迴圈

Agent 以安裝目錄中的 Python 腳本進行排程（下列為 Agent 內部指令，非一般使用者必須手動執行的步驟）：

```bash
sh "<SKILL_ROOT>/scripts/run-python.sh" "<SKILL_ROOT>/scripts/review_queue.py" --target "<TARGET_ROOT>" --init --batch-size 10 --compact
```

Windows PowerShell 對應指令：

```powershell
& "<SKILL_ROOT>\scripts\run-python.cmd" "<SKILL_ROOT>\scripts\review_queue.py" --target "<TARGET_ROOT>" --init --batch-size 10 --compact
```

首次執行可先用 `sh "<SKILL_ROOT>/scripts/run-python.sh" --check`（Windows：`& "<SKILL_ROOT>\scripts\run-python.cmd" --check`）唯讀檢查 Python 3.10+ 和相依套件。啟動器會依序嘗試 `python`、`python3`、`py -3`；若不可用，保留既有進度並回報安裝指令，不自動安裝。

**按需載入標準文件（P5）**：`--compact` 只回傳精簡待辦；每條規則仍須呼叫 `review_queue.py --target "<TARGET_ROOT>" --detail-id <規則ID>`，依輸出 `next_checks[].standard_documents` 的路徑（相對 `SKILL_ROOT`）實際讀取對應的 `docs/*.md`。同一執行工作階段已讀且未變更的文件可重用；對照多項標準時須讀全數對應文件，並依 YAML 規則與真實來源執行查核。標準文件缺失時不可把該對照宣稱為已審查；共同結論限制以 [SKILL.md](../SKILL.md) 為準。

1. 若受測專案已存在 `assessment.json`，先讀取並保留原有 Finding、證據及完成進度；否則才建立 70 項待審查草稿。
2. 依 `next_checks` 清單及 `--detail-id` 的 `decision_guidance`（70 項判定矩陣）逐條搜尋程式碼、追蹤呼叫鏈及組態，記錄真實檔案路徑、行號、方法、證據與理由。能以充分靜態證據判定的控制不得因欠缺非必要動態測試一律列為 review；已證實弱點直接 fail 並保留 Finding。
3. 每項審查後記錄 `execution.state`（`pending`、`completed`、`blocked`）以及 `status`（`pass`、`fail`、`review`、`na`）；**不能因待辦清單列出某規則就當作完成**。
4. 每批保存 `assessment.json` 並重新取得下一批；全部 70 項須有真實逐條證據，且 `source_coverage.missing_source_file_count=0`、`review_integrity_errors=[]`、`rule_integrity_errors=[]`、`ready_for_report=true`，才生成最終報告。
5. 真的無法繼續時保留所有進度與實際錯誤，不得把部分結果當成最終交付。

若規則的符合性結論確實需要額外部署／政策／人工／動態佐證，且無法由充分靜態來源與設定證據取代，才使用 `status=review` 並明列已查證內容、來源證據和具體缺口，允許 `execution.state=completed`。**每項 pass/fail/review 必須有可定位的 `checks[].evidence[]`；單靠 inspected_paths 或制式理由不算已完成。** 尚未執行的規則不可標記為 `review` 或 `completed`，也不得為通過驗證虛構工件。

找到弱點時以真實證據建立 Finding，保留風險、影響及改善建議，繼續其餘審查；**本 Skill 不修改受測原始碼，亦不要求先修復才能產生報告**。

判定矩陣位於 `policies/review-decision-matrix.json`：`static` 主要由程式碼／組態判定；`hybrid` 僅在具體外部條件阻斷結論時待確認；`external` 必須有可追查的部署／制度／測試佐證才可 pass。實際無足夠證據時不強行通過，保留進度並重審。`review_queue.py` 的 `rule_integrity_errors`／`recheck_rule_ids` 會回送只附宣告或模板理由的 completed 規則。

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

`assessment.scope` 是描述文字。實際審查檔案須由通過驗證的 `assessment.file_reviews` 配合每條已完成規則的 `execution.inspected_paths` **雙向核對**，不能把檔名搜尋或專案盤點結果當作已審查。

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
