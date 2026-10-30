# 進階使用與完整審查流程

此頁收錄 README 省略的進階操作。一般使用者只需在受測專案的 Codex 對話中輸入 `$security-code-review`（Claude Code 為 `/security-code-review`）。

## Python 執行環境

啟動完整或分類審查前，**先依 [Skill 的 Python 固定程序](../SKILL.md#python-執行環境確認與固定兩種模式共用) 執行啟動器的 `--resolve`、`--check`**，並在同次審查全部命令維持 `SECURITY_CODE_REVIEW_PYTHON_PINNED`。無法執行時依回傳診斷確認 PATH／WSL／沙箱／相依套件，不得以「使用者沒安裝」取代診斷。

## 完整審查執行 Log 與效能追蹤

正式 70 項審查執行時，Agent 先呼叫：

```bash
sh "<SKILL_ROOT>/scripts/run-python.sh" "<SKILL_ROOT>/scripts/review_log.py" --target "<TARGET_ROOT>" start
```

每次執行的 Log 追加保存於 `TARGET_ROOT/reports/security-code-review/logs/<run_id>.jsonl`；同目錄有 `<run_id>-summary.json` 與 `latest.json`。跨次續跑保留 `review_id`、更新 `run_id`；若確定要新審查，加 `start --new-review`。

每次成功整合一批實際檢核證據後，Agent 依所處階段記錄真實進度。例如：

```bash
sh "<SKILL_ROOT>/scripts/run-python.sh" "<SKILL_ROOT>/scripts/review_log.py" --target "<TARGET_ROOT>" checkpoint --phase first_pass --completed-rules 12 --reviewed-files 80
sh "<SKILL_ROOT>/scripts/run-python.sh" "<SKILL_ROOT>/scripts/review_log.py" --target "<TARGET_ROOT>" checkpoint --phase second_pass --second-pass-rules 6
```

數字為範例，不得直接套用或估算。Agent 可另外記錄 `--verified-callsites` 與實測 `--input-tokens`／`--output-tokens`。結構索引、佇列、證據整合與正式報告 CLI 各自記錄耗時及退出碼；Log 不收集原始碼全文或金鑰。

連續四次 checkpoint 無實際進展、且至少 15 分鐘沒有進展時回傳退出碼 3 並記錄 `stalled`。實際進展包括已完成規則、已審查檔案、已驗證呼叫點、第二輪規則數，以及正式整合交易序號（`integrated_transactions`，每次 Stage／Integrate 成功提交即遞增）；`review_queue.py --compact` 會自動回報交易序號，因此第二輪或已完成證據修訂期間規則數不變也不會誤判，整合一再被拒則仍會停滯。此後完整審查 CLI 會直接拒絕執行，避免重試空轉；保留全部原始審查紀錄與 Finding，先診斷阻塞原因。重新啟動用 `start`；人工結束用 `finish --status interrupted`／`blocked`。**這是由 Agent 主動回報的檢查點，不是常駐背景監控。**

`--compact`、`--detail-id` 查詢只提供未驗證的進度預覽，`ready_for_report` 永遠是 `false`；不能使用預覽來源覆蓋率交付。正式驗證必須執行 `review_queue.py`（不帶上述兩參數）、`review_safety.py --validate`、`complete_review.py` 與嚴格報告驗證。`--mode incremental` 只對來源 SHA256 與索引契約相符的結構快取生效，不沿用任何安全判定。

完整效能診斷、批次 Skeleton、唯讀工作分片與 Roslyn 編譯快取的操作及保護條件見 [效能與受控分工指引](review-performance.md)。

## 受測路徑與執行位置

- `SKILL_ROOT`：Skill 安裝目錄，保存 `SKILL.md`、規則、Schema、報告模板及 Python 腳本。
- `TARGET_ROOT`：實際受測專案，Agent 在此讀取程式碼、Git 版本及設定；結果一律寫到 `TARGET_ROOT/reports/security-code-review/`。
- 使用者指定路徑時，可呼叫 `$security-code-review /path/to/project`；不指定時使用目前受測專案。
- 對話指令不是系統 Shell 指令；Agent 必須實際閱讀來源檔，Python 腳本只負責排程、資料驗證及報告生成。

## .NET 專用分析器（未來擴充 .NET Framework／Vue）

本階段 `scripts/lib/analysis_adapters.py` 僅啟用 `dotnet-modern` Adapter。此 Adapter 支援 `net10.0`，並使用 `dotnet msbuild <csproj> -getProperty:TargetFramework,TargetFrameworks,TargetFrameworkVersion` 評估從父層 `Directory.Build.props`／`Directory.Build.targets`、`<Import>`、條件式屬性實際繼承的 TFM；不執行建置／還原目標，不修改受測專案。僅限沒有動態屬性與匯入的直接 TFM 採 XML 字面值。需安裝支援此命令的 MSBuild 17.8+（dotnet SDK 8+）；若 SDK 無法評估目標或屬性未展開，明確 `blocked`、保留日誌與進度，不能用字串搜尋假設成功。傳統 .NET Framework、Vue 及混合專案目前會拒絕完整審查，而非默默跳過；未來可增加 Adapter，而不改動共用的 70 條規則、逐檔證據契約或報告格式。

Agent 在開始佇列之前先執行下列**結構索引準備**（初次 full，重跑可改 incremental）：

```bash
sh "<SKILL_ROOT>/scripts/run-python.sh" "<SKILL_ROOT>/scripts/analysis_prepare.py" --target "<TARGET_ROOT>" --mode full
```

Windows PowerShell：

```powershell
& "<SKILL_ROOT>\\scripts\\run-python.cmd" "<SKILL_ROOT>\\scripts\\analysis_prepare.py" --target "<TARGET_ROOT>" --mode full
```

新增第二層審查證據閘門：`file_reviews[].rule_reviews` 與 `checks[].evidence` 每筆來源證據都必須引用實際相關的控制邏輯；不得以方法宣告、`using`、欄位、泛用設定，或跨檔共用的排除理由來湊數。當 70/70 completed 仍未通過，必須使用不帶 `--compact` 與 `--detail-id` 的 `review_queue.py` 進行正式查核，顯示 `recheck_rule_ids` 和需重新驗證的 `next_checks`。這些是補查工作，不改寫 Findings。

Roslyn 索引保留型別、方法起訖行、呼叫所在方法、接收者型別及合成編譯得到的符號／介面實作候選；`cross_file_call_hints` 記錄不截斷的跨檔候選與呼叫點 ID。`semantic_*` 仍不等於真正專案建置／執行期目標，`receiver_type_candidate` 和 `name_only_ambiguous` 亦須人工核對。新索引下須依 [跨檔呼叫點結案要求](review-integrity-guards.md#跨檔呼叫點必須人工結案) 完成 `callsite_reviews`；未解歧義不得將跨檔規則標為 completed。與 CodeGraph 不可用時一樣回退為人工查核，不能假裝已追蹤資料流。

這一步也會將每個來源檔的多條高辨識度規則候選存到 `analysis/structure-index.json` 的 `rule_candidates`，並回傳候選檔案與關聯數。增量模式只會在來源 SHA256 未變、候選分析器版本相同時重用候選；候選只供定位，不會寫入 pass/fail/completed。`review_queue.py` 的完整與精簡模式都保留下一批最多 30 個未審查檔案的候選規則提示；精簡模式不執行全量安全守門。

這一步偵測 CodeGraph 與 .NET SDK 8+ 的 Roslyn。CodeGraph 須先由使用者在受測專案執行 `codegraph init`；缺少 CodeGraph／SDK 時只退回既有搜尋與人工分析，**不得視為已執行 Roslyn 或完整 SAST**。Roslyn 只提供 C# syntax tree 的 types、methods 與 invocation 候選（非跨方法污點證明）；Agent 仍要核對程式碼及配置。增量快取只共用相同 SHA256 與相同分析器版本的結構資料，不沿用過期安全結論。

Token 優化佇列與來源批次：

```bash
sh "<SKILL_ROOT>/scripts/run-python.sh" "<SKILL_ROOT>/scripts/review_queue.py" --target "<TARGET_ROOT>" --init --batch-size 10 --compact
sh "<SKILL_ROOT>/scripts/run-python.sh" "<SKILL_ROOT>/scripts/review_queue.py" --target "<TARGET_ROOT>" --detail-id CR-05
sh "<SKILL_ROOT>/scripts/run-python.sh" "<SKILL_ROOT>/scripts/review_queue.py" --target "<TARGET_ROOT>" --compact --source-batch-size 60
```

對應來源可額外查詢保守的 .NET 安全規則候選（僅線索，並非資安結論）：

```bash
sh "<SKILL_ROOT>/scripts/run-python.sh" "<SKILL_ROOT>/scripts/analysis_candidates.py" --source-root "<TARGET_ROOT>" --path "src/Web/Controllers/AccountController.cs"
```

若出現 `AC-04`、`IN-03`、`AU-09` 等候選，必須核對實作、呼叫端和資料流，將所有真正適用的規則建立多對多 `file_reviews[].rule_reviews`／`checks[].execution.inspected_paths` 關聯；不適用時可使用 `candidate_exclusions` 按規則記錄至少 40 字的具體理由。不可讓候選工具自行完成檢核。只有 `using`、註解、方法宣告的來源不算完成證據。缺外部佐證的 `review` 應指定缺少的工件和查核範圍，不得套用部署／政策／動態測試通用清單。

精簡佇列列出待辦、有限的來源候選與未驗證進度；唯在 70/70 狀態下補查既有的規則／逐檔證據錯誤，不進行全量安全守門；逐條檢核前以 `--detail-id` 取得所有標準對照，結案時不帶兩參數重新完整驗證。其餘逐檔 10 類篩選、70 項完成證據、Finding 與原有報告驗證均**不可略過**。

執行器若提供實際 Token 數，可選擇寫入統計：

```bash
sh "<SKILL_ROOT>/scripts/run-python.sh" "<SKILL_ROOT>/scripts/token_metrics.py" --target "<TARGET_ROOT>" --executor "Codex CLI" --run-id "review-001" --input-tokens 100 --output-tokens 50 --cached-input-tokens 10 --tool-calls 3
```

數字必須是實際 API／執行器回傳資料，上述僅示範命令格式。統計位於 `reports/security-code-review/analysis/token-usage.jsonl`，不包含程式碼或推論出的 Token 值。

## 審查完整性檢查與受控唯讀分工

執行 `analysis_prepare.py` 後，先以 `review_safety.py --target "<TARGET_ROOT>" --plan` 取得 70 項的最小責任範圍及需追查的來源／關聯候選。每檔依序完整篩選全部規則；`cross_file` 和 `project` 類別須補足結案證據。透過 `--stage <JSON路徑>`、`--integrate` 進行工作中結果的獨立暫存與有衝突檢查的整合，並以 `--validate` 確認結案及工作樹版本；正式結果仍維持原有 assessment Schema。

新機制拒絕來源快照異動與混合 Git Revision，並要求跨檔結案及全專案責任確認。若原始碼真的異動，須先調查、明確 `--snapshot-refresh` 並重新執行 `analysis_prepare.py`，再重新覆核全部無法證明未受影響的安全結論；既有 Findings 與歷史證據保留。不要把索引候選當作已完成的呼叫鏈，也不能複製制式結案文字。

來源快照更新採「完整性保護的影響閉包」：若只有 Git Revision 改變、受測來源 SHA256 完全相同，明確執行 `--snapshot-refresh` 只更新經 Manifest／Journal 封存的版本錨點，不重置既有規則、跨檔結案與 Findings。若來源異動，僅對有可信舊索引／來源證據／呼叫鏈關聯的規則縮小重查範圍；新增／刪除檔案、組態異動、失效索引、未知來源或無法界定影響時一律保守擴及全部 70 項。保留未受影響結案，重建索引後仍須通過正式關聯驗證。

來源異動後的 `analysis/recheck-required.json` 是權威待辦清單；`--diagnose-first-pass` 的 `recheck_rule_ids` 直接引用此清單，並同時揭露其他阻塞。對新格式 `schema_version=2` 的待重查規則，`--stage` payload 必須包含同一規則的新 `checks[]` 證據，以及 `recheck_proof` 對應的 `snapshot_fingerprint`、`source_hashes`（目前快照中全部已變更且仍存在的來源路徑與 SHA256）、`removed_source_paths`（已刪除來源路徑，無則空陣列）和至少 40 字的 `verification_summary`。只重送舊 completed 資料、填入舊快照雜湊或未核對來源均不可解除待辦；完整性守門與 Finding 修訂授權不因此放寬。

詳細 JSON 實例、參數、版本限制與不支援的語意分析類型見 [完整性守門指引](review-integrity-guards.md)。

## 安全控制有效性與繞過路徑驗證

在來源完整性與跨檔呼叫鏈查核之外，對靜態與混合規則的 `completed + pass`，必須按 `review_queue.py --detail-id` 提供的 `control_effectiveness_guidance`，逐項確認安全控制入口、實際執行分支、受保護操作、失敗時拒絕行為與所有最低繞過情境。Agent 將真實來源行號、完整追查結果、Git Revision 與 SHA256 寫入批次 JSON 的 `control_verifications`，由 `review_safety.py --stage / --integrate` 保存於 `analysis/control-verifications.json`。未補齊時 `--validate` 與 `ready_for_report` 不會通過；`fail`／`review`／`na` 仍遵循現有判定階梯，不能因欠缺控制有效性查核紀錄擅自改判。

**安全控制必須真實查核，不是套用繞過清單就自動 Pass。** 詳細 JSON 契約與例外見 [安全控制有效性與繞過驗證指引](control-effectiveness-review.md)。

## 待確認判定與外部證據驗證

現有判定階梯保持不變，新增對 `completed+review` 的證據守門：Agent 必須**實際查完靜態控制及跨檔關聯**，證明仍存在會改變結果的外部工件缺口，才在正式 `decision_reason` 以「待確認：」列出工件。未完成的靜態調查保留 `pending/blocked`；已證實的程式碼缺陷 `fail`＋Finding；缺非必要測試不得當作外部缺口。由 `review_queue.py --detail-id` 的 `decision_adjudication_guidance` 讀取規則 `mode`、`manual_boundary` 與必查欄位，將來源證據和外部問題保存於 `decision_audits`，以原有 `review_safety.py --stage / --integrate` 整合。判定驗證機制不自動改寫任何既有結論，詳細流程見 [待確認判定與外部證據指引](review-decision-adjudication.md)。

## 審查證據完整性與交易復原

新版索引以 SHA256 交易鏈連結正式 assessment、來源快照與各階段工作證據。新審查使用 `review_queue.py --init` 建立起點；既有審查須先人工核對後明確執行 `review_safety.py --seal-integrity`。每批 `--stage` 綁定目前交易版本，`--integrate` 預寫可復原的多檔交易日誌；中斷後核對來源及 SHA256 再執行 `--recover-integrity`，不得任意重算雜湊或刪除 Finding。詳見 [證據完整性與安全復原](evidence-integrity.md)。

## 主代理第二輪反向複核

第一輪須先完成 70 項與所有逐檔／跨檔／證據守門，再使用 `review_safety.py --begin-second-pass` 固定第一輪判定與來源快照。主代理之後重新閱讀實際程式碼，逐項從攻擊者觀點檢查反例，高風險規則至少兩個不同攻擊面。透過 `review_queue.py` 的 `second_pass.pending_ids` 續行，`--detail-id` 的 `adversarial_guidance` 提示反例要求；第二輪資料經 `adversarial_reviews` 暫存整合。任何矛盾先修訂原始判定／Finding 再記錄裁決，不得只重複第一輪理由。**同一代理的第二輪自我複核不等於真正獨立審查。** 詳見 [第二輪反向複核指引](adversarial-second-pass.md)。

## 反向複核的實質攻擊假設

新版索引要求 `adversarial_reviews` 將第一輪固定判定理由與第二輪重讀證據連結，逐一記錄攻擊向量、前提、預期效果、實際查核分支與結果。高風險規則須兩個不同攻擊向量；大量重複的文字、泛稱的攻擊面或同一個來源行套用全部規則都不能結案。若第二輪推翻原判定，須具體追查漏判原因，並將已確認弱點連結正式 Finding。詳見 [反向複核指引](adversarial-second-pass.md)。

## 真實審查品質驗收與回歸比較

固定 16 個案例必須逐一由同一版 Skill 實際完成 70 項、安全證據、第二輪複核及正式 HTML／JSON 後，才可執行 `sh "<SKILL_ROOT>/scripts/run-python.sh" "<SKILL_ROOT>/scripts/quality_acceptance.py" --workspace "<CASE_WORKSPACE>" --output "<QUALITY_RESULT>.json"`。正式驗收核對未修改的案例來源、`ready_for_report`、Finding、跨檔來源、控制證據及已知外部缺口；`--compare` 會阻擋先前已通過案例退步與新增漏報／誤報。未提供 16 份完整工件時，結果為 **blocked**，不得將合成 CI 測試稱為品質實測通過。Token 統計僅接受 `token_metrics.py` 保存的執行器真實紀錄。詳見 [品質驗收指引](quality-acceptance.md)。

## 全 70 項品質驗收與真實專案回歸

執行 `sh "<SKILL_ROOT>/scripts/run-python.sh" "<SKILL_ROOT>/scripts/quality_gate.py" --matrix-only` 取得全部 70 項判定及反例證據契約覆蓋結果；對已完成的 Northwind 或其他真實專案，使用 `quality_gate.py --target "<TARGET_ROOT>" --output "<QUALITY>.json"` 檢查正式審查結果、判定與反例品質、來源 100% 覆蓋、第二輪及 HTML／JSON 完整性。對相同來源版本使用 `--compare "<PREVIOUS>.json"` 找出既有 Fail／Finding 或來源證據退步。正式品質驗收必須使用**完整權威佇列驗證**；`--compact` 與 `--detail-id` 僅供查詢，`ready_for_report=false` 不能當成正式驗收結論。正式報告未生成前，品質驗收仍會保持 `blocked`，須先解決真實證據缺口並以 `complete_review.py` 交付報告。固定 16 案例另由 `quality_acceptance.py` 進行真正 Agent 審查的品質驗收；這些指令**不執行代理、不憑 CI 或合成測試宣稱模型準確率**。詳見 [品質驗收](quality-acceptance.md)。

## Codex App 指定分類審查（部分審查報告）

在 Codex App 已開啟的受測專案對話中，選取／輸入 `$security-code-review` Skill，附上 `--categories` 即可。這是**交給 Agent 解析的 Prompt 參數**，不是要求使用者手動跑 Python 指令：

```text
$security-code-review --categories AC,AU
```

也可使用明確敘述：

```text
使用 $security-code-review Skill，對目前專案僅執行 AC、AU 分類。
--categories AC,AU
逐條查閱實際程式碼、跨檔控制鏈與安全繞過路徑，保留 Finding。
同一主代理完成各分類獨立第二輪複核；各自生成並驗證部分 HTML／JSON，
不得將部分報告視為正式 70 項完整審查。
```

此模式 **AC 8 項、AU 10 項分別存檔**，不更動正式全規則審查。沒有指定 `--categories` 時才執行下方的完整 70 項 `/goal`。分類模式 Agent 必須：

1. 按 `SKILL.md` 的模式分流閱讀 [分類審查操作契約](category-review.md)，先驗證分類及正式規則主檔，再建立分類進度與共用索引，不得使用正式 `analysis_prepare.py` 或無分類參數的正式 `review_safety.py` 更新分類資料。
2. 同批選多類可以共用原始碼索引，但每分類逐條真實審查、獨立 `--stage/--integrate`、完成第一輪及第二輪安全證據守門；逐檔適用性篩選只針對當前分類，必要的跨檔來源仍全部追查。
3. 各分類 `safety_valid=true`、`remaining_ids=[]`、`second_pass.pending_count=0`、逐檔來源覆蓋率 100%，才用 `complete_review.py --categories AC,AU` 產生 AC、AU 各自 HTML／JSON，並以 `validate_report.py --source-root "<TARGET_ROOT>" --strict-sources --categories AC,AU` 驗證。分類 `ready_for_report` 保持 `false`，**不得**套用正式完整模式的 `ready_for_report=true` 守門。
4. 若分類資料尚未完成、來源快照異動或發布／驗證出錯，保留原有 Finding、審查進度與可復原證據，說明原因，不得偽造 Pass 或自動將未選分類標為 N/A。

完整 CLI 操作、Windows／Linux 啟動器與資料路徑請見 [分類審查操作契約](category-review.md)。指定全部十類仍然是十份部分報告；不能當作正式 70 項結果。

## 第一輪既有證據修復（逐檔證據、關聯、控制鏈及正式驗證）

`assessment.json`、`file_reviews`、Findings 與 Journal 都屬正式審查資料；重新載入不代表已經驗證。遇到大量第一輪 blocker 時，使用唯讀清單排定優先順序：

 ```powershell
python "<SKILL_ROOT>/scripts/review_queue.py" --target "<TARGET_ROOT>" --diagnose-first-pass
python "<SKILL_ROOT>/scripts/review_queue.py" --target "<TARGET_ROOT>" --repair-plan --source-batch-size 30
```

- **逐檔證據重讀**：先重新閱讀重複模板、證據無關及高度扇出的檔案；空白 `rule_reviews` 不代表尚未審核，須依實際檔案確認十類責任。
- **規則關聯核對**：針對 `missing_rule_review_ids`、`inspected_paths_diagnostic` 的規則／檔案關聯逐一核實；不可將診斷列表自動轉換為補寫 payload，也不得擅自移除真實關聯。
  - `missing_rule_review_ids` **只表示真正適用規則的逐檔紀錄缺口**；`na_inspection_rule_ids` 是為判定不適用而閱讀的來源，**不得**為這類路徑新增假 `rule_reviews`。
  - `verified_na_inspection_rule_ids` 已由正式逐檔驗證器承認；`unverified_na_inspection_rule_ids` 仍須針對整個檔案的 SHA256、十類篩選、來源行號及規則本身的搜尋證據補查。即使 `na` 已確認適用性，來源證據不合格仍是 blocker。
  - `observed_source_issue_details` 限列每檔前 12 筆權威錯誤（包含規則 ID 及原始診斷文字）。使用 `--diagnose-first-pass` 核對未列出的錯誤，優先分析來源錯誤與實際控制呼叫；不得依錯誤字串自動改判。
- **控制鏈補查**：補查跨檔鏈、控制有效性、正式判定與反向攻擊情境、失效位置、外部責任與來源快照；不因某條控制缺少關鍵字就直接放寬 Verifier。
- **合法修訂與正式驗證**：經本人核對真實來源及既有 Finding 後，以 `review_safety.py --stage` 暫存並使用 `--integrate --allow-revision` 合法修訂；每批整合前增量驗證變更檔的正式來源關聯，明顯無關行號與擴大的重複模板會拒絕寫入。最後重新執行 `--diagnose-first-pass`，只有 `ready_for_second_pass=true` 才能啟動第二輪；正式報告使用非 `--compact` 的完整佇列驗證。

正式證據修復每次最多先選取 5 個高阻擋檔案：對每個檔案閱讀實際程式碼，逐一核對 `observed_source_issue_details`、十類 `category_screening`、適用規則、控制鏈與 Finding；保留未更動的真實證據。逐批整合成功後重新診斷，如 `blocker_signature` 未變則必須先找出新證據缺口，不能盲目重試。

`--repair-plan` 是唯讀提示，不提供「一鍵清除 blocker」；僅靠上傳 `assessment.json` 缺少目標來源快照、完整性 Manifest 與 Journal 時，不能在別處產出合法覆寫 payload。對已有不合格的未動部分，整合時不直接改寫；正式驗證仍照常拒絕。

### 規則層級第一輪修復排程（唯讀，不代替正式證據）

`--repair-plan` 除了原本的 `priority_files`，也提供 `rule_repair_tasks`、`rule_work_matrix` 與 `task_coverage`。`candidate_repair_file_count=0` 不代表沒有規則層級缺口。每筆任務包含 `task_id`、`rule_id`／`rule_ids`、`blocker_indexes`、`blocker_details`（原始訊息、權威類別與規則）、`artifact`、`priority`、`depends_on`、`status=pending` 及 `requires_source_verification=true`；以 `blocker_signature` 對帳同一份診斷的原始索引。

工作類型依序為：**正式檢核來源證據、跨檔控制鏈／候選關聯、規則結案、控制有效性、外部責任與靜態來源裁決、檢核摘要**。內部機器代碼只在 JSON 中使用；使用文件不以開發階段名稱描述功能。每筆阻塞只歸屬一種修復工作；不認得的訊息、缺少合法規則歸屬、錯誤筆數不符都保留並使 `task_coverage.valid=false`，不得產生推測的安全結論。

**執行時只能依 `execution_batches` 的順序進行。** 每批都有 `batch_id`、`rule_ids`、`task_ids` 與 `depends_on_batch_ids`，前置工作必須位於更早的執行批次。每批最多涉及 8 條規則；同規則的「規則結案」與「控制有效性」在同批安排。跨規則共用任務只執行一次，且在相依工作之前；若任何任務缺少批次、被排入兩次、跨批次依賴逆序、存在依賴循環或超過批次上限，`task_coverage.execution.valid=false` 且總體 `task_coverage.valid=false`。輸出中的 `rule_repair_batches` 與 `shared_rule_repair_batches` **僅是按規則分組的輔助檢視，不具執行順序**，不可直接依它們的陣列次序整合。

工作依賴按**同一條規則**建立：規則結案／有效性須先查明其來源證據與控制鏈缺口；外部責任及靜態來源裁決須先取得該規則的正式來源證據。跨規則任務的依賴同樣納入批次拓樸檢查。不同規則可以同時進行**唯讀查證**，但正式寫入必須由單一主代理按 `--stage`／`--integrate --allow-revision` 依序完成；未經另行授權不得修訂 Finding。

正式完整模式若需自動協調既有證據的實際修訂與抽樣，可使用 [受控修復波次（Wave 0～4）](review-repair-waves.md)。其正式交易仍須 Agent 提供真實來源證據、明確授權，不能僅根據排程或錯誤字串補寫結果。遇到 Wave 2 `inflight` 與 staged 未提交且無法 `--reconcile` 時，依 [單筆未提交交易唯讀預檢／受控隔離](review-repair-waves.md#stage-成功但-integrate-拒絕僅取消確定未提交的單一批次) 操作，先確認本機 Skill 已更新；嚴禁重送、改 checkpoint 或刪除原始 staged。

### 批次回歸、證據抽樣與停止條件

先保存權威診斷 JSON，經來源實際重讀與合法整合後，使用唯讀比較取得新增／消失的阻塞與停止建議：

```powershell
python "<SKILL_ROOT>/scripts/review_queue.py" --target "<TARGET_ROOT>" --diagnose-first-pass > "<BEFORE_DIAGNOSTICS>.json"
# 來源查證、合法 stage/integrate 後：
python "<SKILL_ROOT>/scripts/first_pass_repair.py" --target "<TARGET_ROOT>" --previous-diagnostics "<BEFORE_DIAGNOSTICS>.json"
```

若 `batch_regression.should_pause=true`，回傳退出碼 **3**；新增權威阻塞類型、新修復工作類型、4 筆以上新增不同阻塞、未知訊息或來源／完整性錯誤均須暫停。執行者還必須核對新增／刪除的 Findings、實際來源 SHA256、Manifest／Journal 及合法備份；唯讀比較**不**取代正式驗證與復原，也不能任意回溯舊版 Journal。證據失配時先執行 `review_evidence_recovery.py --plan` 與 `hash_audit.py --target "<TARGET_ROOT>"`；不得自動重算雜湊或清除既有 Finding。

人工抽樣以本次全案實際修訂的不同規則數 N 為母體，至少 `min(N, max(5, ceil(0.1*N)))` 條（N=0 時 0），採可重現的風險分層抽樣；Finding 修訂、Fail 判定異動及重大控制責任變更須全部核對。**抽樣與簽認尚屬人工程序，不是此唯讀排程器已完成的動作。**

NuGet 漏洞掃描失敗不是 `ready_for_report` 的獨立退出碼守門，但依賴套件規則仍須符合真實來源、外部掃描失敗詳情與正式判定證據；Restore 失敗不能宣稱不存在漏洞。第二輪仍須完成 70 條規則的反向核查與既定高風險來源抽樣。同一代理重審為非獨立複核，其他代理或人員的獨立驗證須如實揭露；獨立性報告欄位與 NuGet 排障不在本次排程器的自動化範圍內。

本次回歸快照（`blocker_signature=902cf1859a4df9415b6431f2eff70144de11d1072d5e0c031513e58bb62f95dd`）共 155 筆阻塞，按上述六種工作類型依序為 **9／9／67／53／8／9**，涵蓋 70 條規則，原始規則分組為 9 批。固定數字僅限這份指紋的回歸測試；一般診斷不能以這些常數作為放行條件。

## 證據內容備份、可信復原與重新取證

正式交易以來源快照與 Journal SHA256 為驗證依據，另在 `analysis/integrity-backups/<sha256前兩碼>/<sha256>.json` 以內容定址、去重保存每一份受控證據的**原始 bytes**。新版初次封存及每次交易，在記錄 Journal 前都先備份原始與預期新版本；不會把備份存在不可重建的 SHA256 字串中。舊版既有 Journal 不追溯宣稱有備份。

先以唯讀診斷判斷是否有真正可恢復的資料：

```powershell
python "<SKILL_ROOT>/scripts/review_evidence_recovery.py" --target "<TARGET_ROOT>" --plan
```

- `--checkpoint`：正式受控檔案與當前 Manifest／Journal 完全相符，但備份尚未建立或已遺失時，明確建立備份檢查點並新增正式交易；不接受原證據不完整。
- `--restore`：僅從雜湊匹配的持久化備份還原最新 Journal 所指定的原始內容，先完成全部檔案核對，再還原及追加 `backup-restore` Journal。當正式檔案存在但內容不符時須額外指定 `--allow-damaged-replacement`，不可無聲覆寫。
- `--recover-integrity` **仍只處理未完成的 `integrity-pending.json`**，不能拿來找回歷史檔案；缺少或遭竄改的 Journal／Manifest 不得以重算 SHA256 方式強行通過。
- **若本次遺失的檔案沒有可信備份**，只能取得使用者明確確認後使用 `--archive-for-recheck --acknowledge-evidence-loss`，將原報告、10 個（或當時實際數量）Findings 與完整歷史隔離到 `reports/security-code-review-archives/`，在新報告下另存 `analysis/prior-findings-unverified.json` 供人工重新查證。**不會把舊 Findings 當作新審查已確認結論**；需先重新閱讀原始碼、確認後透過正式 `--stage`／`--integrate` 加回。再執行 `review_log.py start --new-review`、`analysis_prepare.py` 與 `review_queue.py --init`，全部 70 項與來源重新取證。不得用 `--seal-integrity` 重設已損壞的舊鏈。
- 備份、復原、重新取證只處理報告資料，不修改受測專案來源碼。舊版雜湊若缺乏原始 bytes，不可能藉此工具逆向恢復。

## 預先授權邊界

`/goal` 的**實際使用者輸入**可以事先包含限定本專案、本次審查的**全部流程授權**，供長時間無人值守執行時省去每批重問。下方範本的授權段落預先涵蓋：completed 證據修訂（`--allow-revision`）、Finding 更正（`--allow-finding-revision`）、誤判 fail 受控撤回（`--allow-fail-withdrawal`）、證據備份還原（含 `--allow-damaged-replacement`）、無可信備份時封存重審（`--archive-for-recheck --acknowledge-evidence-loss`）、未提交 Wave 批次的受控取消（含 staged-only 例外）、交易中斷復原與既有結果封存（`--recover-integrity`／`--seal-integrity`）、來源異動後的 snapshot-refresh 重查，以及多代理 `--renew-budget`／`--renew-probe` 續期。每項仍須先通過該工具自身的唯讀預檢與真實重新查證；單純讀取文件、引用範例或沒有使用者輸入，不等於授權。跨專案或超出本次審查範圍的變更仍需另行確認；這項授權不能取代任何完整性驗證。

## Codex 可選 `/goal` 完整審查指令

在支援 `/goal` 的 Codex 版本中，於**受測專案的對話**輸入。以下範例**明確選用主代理＋最多 3 位子代理**，Skill 名稱可攜。一般 `$security-code-review` 仍預設單代理，分類 `--categories` 不啟用多代理：

```text
/goal 使用 $security-code-review --multi-agent --agents 3 Skill，對目前專案執行完整、具備真實程式碼證據的 70 項資安檢核。

授權（本人明確同意）：本次為長時間無人值守執行，僅限本次指定受測專案與本次完整審查，以下操作全部預先授權，Agent 不必逐批或逐項重問；每項仍須先重新閱讀真實原始碼、核對來源快照及安全控制證據，並通過該工具自身的唯讀預檢：
- 以 --integrate --allow-revision 修訂既有 completed 證據。
- 經重新閱讀證明須更正時，以 --allow-finding-revision 更正既有 Finding（保留 finding_amendments 舊全文與修訂追溯）。
- 重新查證確認為誤判的 fail，附來源反證後以 --allow-revision --allow-fail-withdrawal 受控撤回，原 Finding 全文保留於撤回紀錄。
- 完整性證據遺失時依 review_evidence_recovery.py --plan 核對後 --restore（必要時含 --allow-damaged-replacement）；無可信備份時以 --archive-for-recheck --acknowledge-evidence-loss 封存舊審查後重新取證。
- 未提交 Wave 批次在 --inspect-uncommitted 回報 can_abort=true 時以 --abort-uncommitted --acknowledge-investigation 受控取消，含符合全部條件的 staged-only 例外。
- 人工核對後執行 --recover-integrity／--seal-integrity；來源異動時依 snapshot-refresh 與重查機制重新取證；多代理資源不足時依契約 --renew-budget／--renew-probe 續期。
仍不得修改受測專案程式碼、繞過品質／SHA256／Manifest／Journal 守門、未經來源反證移除既有 confirmed Finding、未經裁決將 fail 改成 pass，也不涵蓋其他專案。

前置：

- 使用目前已包含「review 判定規則收斂」的 SKILL.md（原 claude/tighten-review-decision-rules 分支內容已整合時，以安裝版本為準）。判定一律遵循其中「共同證據與結果判定」的判定階梯；如果目前安裝的 SKILL.md 缺少該段，先回報版本不一致，不得沿用舊判定規則完成報告。
- 於 Agent 實際執行環境透過 `run-python.sh`／`run-python.cmd --resolve`、`--check` 確認 Python 3.10+ 與相依套件，並固定 `SECURITY_CODE_REVIEW_PYTHON_PINNED`。即使命令名稱不可見也要搜尋既有安裝位置；失敗時分辨 PATH、版本／套件與沙箱問題，不得自行繞過或安裝。
- **非 Git 專案不構成子代理降級條件**：`--multi-agent` 維持以來源 SHA256 快照與 Codex 原生工具／強制唯讀試跑判斷；缺 `.git` 時記錄 Git Revision 不可得，只有真正工具或安全隔離失敗才降級。完整性守門失敗仍須阻擋，不得以改成單代理掩蓋。
- 本 `/goal` 選用最多 3 個唯讀子代理。主代理須依 `SKILL.md` 與 `docs/multi-agent-review.md` **自動調用目前執行器實際提供的原生協作工具**，不能只列出派工清單就宣稱已執行；缺工具、真實唯讀沙箱、可信 agent ID 或隔離驗收未過時，記錄原因後**完整降級單代理**。正式判定與寫入始終只由主代理負責。

多代理自動執行（此段是 Agent 必須採取的工具動作，**不是** shell 指令）：

- 主代理確認此回合有真實原生子代理建立、續派及等待工具（名稱例如 `spawn_agent`、`followup_task`，以執行器實際提供者為準），在**正式相同沙箱配置**下實測平行、獨立上下文、強制唯讀、單層委派、失敗復原、封閉回報及第一輪結論隔離等七項條件。使用 `multi_agent.py --probe-template`／`--record-probe` 登記實際 trace；只靠 Prompt 禁寫不得通過。
- 完成來源索引及初始化後，主代理執行 `multi_agent.py --plan --max-agents 3` 與 `--next`；透過原生工具建立**只待命、不讀來源**的 Worker，先取得實際 agent instance ID，才以 `--claim-batch --assignments <JSON>`（或逐筆 `--claim`）綁定 task 與 agent。只有成功 claim 後，才透過原生續派／訊息工具送出完整 Worker Prompt 和 TASK_JSON。派工數量不超過 3、Ledger.workers、執行器可用槽位及 Token 窗口。
- **同批真正並行執行**、等待每個 Worker 完成，而非只等建立成功。主代理將純 JSON 以 `--accept-stdin` 在落地前驗證機敏資料、來源 SHA256、隨機行挑戰、完整閱讀範圍及逐檔十類／規則證據；失敗或逾時明確 `--fail`、依上限重試。未解跨檔符號以 `--followup`、`--accept-followup-stdin` 補查，最後仍由主代理在權威交易後 `--resolve-main`。
- 每批所有 Worker 停止後，主代理執行 `--begin-integration`，實際重讀控制鏈並以 `review_safety.py --stage/--integrate` 正式寫入，再 `--commit-integration` 驗證新 Manifest／Journal，然後自動派下一批。資源不足保留進度，依 `--renew-budget`／`--renew-probe` 契約明確續期，不得自動略過。
- 第一輪通過 `--diagnose-first-pass` 且 `ready_for_second_pass=true` 才能在正式整合窗口執行 `review_safety.py --begin-second-pass`；再以 `multi_agent_second_pass.py --plan/--next` 派給**未參與相同規則第一輪**、可隔離第一輪判定的不同子代理。主代理只接受候選，重新讀取來源、反向查證及裁決，完成全部第二輪與正式報告守門。若原生隔離不足，改由主代理依原第二輪流程繼續，**不得宣稱盲審**。
- 原生工具不存在、沙箱強制唯讀失敗或 agent ID 不可信時，不創造虛構 Worker／trace；保留原有合法進度與 Finding，以單代理繼續完整 70 項、100% 來源、安全控制及第二輪檢核，最終仍須產出並驗證 HTML／JSON。

完成條件：

0. 先執行 analysis_prepare.py，確認全部受測專案均為 .NET Core／現代 .NET；偵測並優先使用可用的 CodeGraph 與 Roslyn。利用既有結構快取減少重複讀取，失敗則回退，但不得把索引當成資安判斷。使用 review_queue.py --compact 取得待辦，每條規則透過 --detail-id 取完整要求並載入實際對應的標準文件。增量只重用結構證據；來源有變更時，依版本快照及可信影響閉包重新查核，不能沿用未重新驗證的安全結論。
   - 新審查由 --init 自動建立完整性封存；已有結果的專案則需先人工核對並執行 --seal-integrity。交易中斷須先核對後明確 --recover-integrity。
   - 完整性證據遺失時先以 `review_evidence_recovery.py --plan` 核對可信內容備份，通過後才執行 `--restore`；無可信備份須經明確同意（本 `/goal` 授權段落已預先同意）保留／隔離舊審查與 Findings 並重新取證，不得重封舊鏈。
   - 執行 review_safety.py --plan，確認全部 70 項的 local／cross_file／project 責任範圍；跨檔關聯候選（DI、Middleware、設定、Endpoint、跨專案引用）必須實際追查。來源快照與結構索引不一致時先排除異動原因，不得混用版本。

1. 完整盤點受測專案的原始碼、設定檔、專案檔、相依套件及相關 CI/CD 設定，建立實際審查範圍。全專案規則即使沒有關鍵字命中，也必須確認控制責任與缺席情況。

2. 逐檔實際閱讀程式碼，依 rules.json 的全部 70 條規則判斷適用性：
   - 不得只依檔名、關鍵字或 Regex 判定完成。
   - 不得只取第一個命中的檢核項目。
   - 不得預設使用 XX-01 或 SI-01。
   - 追蹤適用的程式碼、呼叫鏈、資料流及設定。
   - 一個檔案可關聯多條適用規則，但不得為增加數量而建立無依據的關聯。
   - 每個檔案完成十類適用性篩選；無直接適用項目仍須提出已核對的控制責任及理由，不得制式填入「無直接適用」。
   - 每批完成後使用 `--repair-plan` 唯讀檢查已保存的第一輪證據及未建檔來源；尚有 pending 規則也要回報已完成規則的品質缺口。優先修正重複模板與高扇出檔案；不得等到第二輪前才一次處理整體缺口。

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
   - 對 completed+review 建立 decision_audits：依證據模式核對實際 static_evidence 或可追溯的外部控制責任證據、searched_paths、manual_boundary、外部工件及 blocking_question；open_static_questions 必須為空。只有缺非必要動態測試不得 review，且不能將未完成的程式碼追查列為 static_done_external_pending。
   - 控制由外部平台實施時，依 [外部控制責任證據契約](review-decision-adjudication.md#可查證的外部控制責任適用全-70-項) 核對真實責任歸屬及控制有效性。缺 Workflow、Runner、掃描輸出或程式碼行號本身不是委外證據；不得虛構本地控制執行點。
   - 不得預設所有檢核為 review，也不得僅因未執行動態測試就把靜態可判定項目設為 review。

5. 保留既有 assessment.json、file_reviews、Findings 及所有證據。
   - 對缺乏實質分析的既有 completed 紀錄重新查核。
   - 既有 status=review 的項目，一律依新版判定階梯重新判定；能改為 pass 或 fail 者須更新 status、decision_reason 與必要 Finding，保留原有證據，不得刪除。
   - 不得使用固定模板、批次填入理由或製造檢核結果。
   - 不得修改受測專案原始碼，也不要求先修復弱點。
   - 工作中結果使用 review_safety.py --stage 獨立暫存，再以 --integrate 檢查衝突後整合。多代理模式必須先 `multi_agent.py --begin-integration` 停止派工，再由主代理正式 Stage/Integrate，`--commit-integration` 成功核對交易後才可繼續派工。覆核既有 completed 須有真實重新審查證據及必要的修訂流程，不得覆寫已確認弱點。
   - 本 `/goal` 已明確預先授權本次專案之 completed 證據合法修訂：核對真實來源後可用 `--integrate --allow-revision`，不必逐批重問；Finding 更正、證據還原／封存重審、Wave 受控取消及續期亦依上方授權段落辦理；未在實際使用者指令授權或超出範圍者須另取得明確同意。重新查證確認已完成的 fail 為誤判時，本 `/goal` 亦預先授權依[受控撤回](review-integrity-guards.md#誤判的已確認-fail-受控撤回不刪除-finding)附來源反證後使用 `--integrate --allow-revision --allow-fail-withdrawal`，原 Finding 全文保留於撤回紀錄。仍不得跳過批次證據、Finding 保護、SHA256／Manifest／Journal 守門。

6. 每批保存真實審查結果，持續執行直到：
   - 70 項規則均已實際完成。
   - source_coverage.missing_source_file_count = 0。
   - review_integrity_errors 與 rule_integrity_errors 均為空。
   - assessment.file_reviews 與 execution.inspected_paths 一致。
   - 第一輪以 `--diagnose-first-pass` 的 `ready_for_second_pass=true` 作為建立 baseline 的前置判斷；**不得在第二輪完成之前要求正式 `review_safety.py --validate` 通過**。
   - `analysis/decision-audits.json` 與正式 review_kind／decision_reason、Git Revision 及來源快照一致，所有外部缺口確實會影響結論。
   - 每批均可執行 `--diagnose-first-pass` 與 `--repair-plan`：`pending_rule_ids` 表示未完成規則，`missing_source_paths` 表示尚未通過逐檔驗證的來源，診斷仍需回報已完成規則的證據問題。第一輪 70/70 且 `ready_for_second_pass=true` 才可執行 `--begin-second-pass`。
   - 第二輪採定向反例、不能重掃整棵來源樹：隔離驗收通過時按 `multi_agent_second_pass.py --plan/--next` 派給第一輪未參與相同規則的子代理；子代理僅回傳反例候選。主代理依 `second_pass.pending_ids` 逐項重讀來源、追查反例並正式儲存 `adversarial_reviews`；沒有真正獨立隔離則回退主代理第二輪，須完成所有 70 項及矛盾裁決。
   - 診斷中的 `inspected_paths_diagnostic` 僅彙整**已被正式逐檔驗證拒絕**的規則／檔案關聯：`by_rule` 按規則計數，`by_reason` 區分缺少逐檔紀錄、缺少規則審查及逐檔紀錄驗證失敗；不是新增檔案數或可自動修補清單。`cross_file_candidates` 列出完整未查證關聯 ID；必須核實來源後逐項處理，不能批次核准。
   - 跨檔／全專案規則的結案紀錄完整，沒有未追查或未排除的關聯候選與 open_issues。
   - Git Revision、來源 SHA256 與分析索引一致；來源異動後須依 snapshot-refresh 與重查機制處理，不能直接沿用舊 completed。
   - **完成第二輪之後**才執行 `review_safety.py --validate`，接著執行不帶 `--compact`／`--detail-id` 的 `review_queue.py`，確認正式結果 `ready_for_report=true`。
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

8. 只有第一輪診斷通過、第二輪完整、`review_safety.py --validate` 成功且正式 `ready_for_report=true`，才執行 complete_review.py，產生並驗證 HTML 與 JSON 報告。報告必須能追溯檔案、適用規則、證據與檢核結論，並維持相關規範及附件的獨立查證要求。

9. 僅遇不可恢復的執行／資源限制、缺少必要人工修訂授權、無法取得且不能合法替代的必要證據時才可停止。停止前保留已完成診斷、blocker_signature、來源與 Findings、完整性交易鏈及明確續跑條件，不得宣稱審查已完成。

在所有條件真正完成前，不得以 70/70 completed、100% 檔案覆蓋率或 JSON Schema 驗證通過，直接宣稱已完成實質資安審查。
```

若環境不支援 `/goal`，正常使用 `$security-code-review` 即可。

**本 `/goal` 範例已預選 `--multi-agent --agents 3`。** 若要維持單代理，首句改為 `/goal 使用 $security-code-review Skill` 並移除上方多代理自動執行段落。分類審查仍僅用 `--categories`，不可混用多代理。原生調度和 Fail Closed 規範見 [受控多代理自動調度](multi-agent-review.md#原生-codex-子代理自動調度完整模式)；Worker JSON 驗證成功不等於 70 項審查完成。
單次執行能否完整完成仍受 Agent 實際可用工具與資源限制影響。

## 完整模式第二輪的分層式工作清單

第一輪 `--diagnose-first-pass` 確認 `ready_for_second_pass=true` 後，執行原本的 `review_safety.py --begin-second-pass`，其新 Baseline 會在**既有受控交易檔**建立分層錨點及固定高風險樣本；不用重新掃描全專案。接著唯讀查詢：

```powershell
& "<SKILL_ROOT>\\scripts\\run-python.cmd" "<SKILL_ROOT>\\scripts\\second_pass_layers.py" --target "<TARGET_ROOT>"
```

依 `rule_tasks` 逐項反向核實實際來源、填入 `blind_challenge` 與 `adversarial_reviews`；依 `sample_tasks` 實際重讀未引用高風險來源，把結果放入暫存 JSON 的 `second_pass_samples`，沿用 `review_safety.py --stage`／`--integrate` 原子整合。分批返回工作清單直到 70 項且全部固定樣本完成，再作正式驗證。最多 8 規則／16 個錨點來源檔／4 樣本是預設**工作清單**上限，`token_hint_per_batch` 只能作執行器預算提示，不能冒稱已限制工具 Token。超出限額或遇必需追查的例外路徑，保留 checkpoint 後分批續跑，未完成不得交付。參見 [第二輪分層契約](adversarial-second-pass.md#分層第二輪完整-70-項模式)。

## 跨檔控制鏈的實際來源驗證

新版結構索引要求跨檔規則在原有 `rule-closures.json` 內提供真實 `control_trace`（已閱讀節點、確認的關聯、實際來源行號），並逐一用證據驗證呼叫點與排除候選。單靠文件清單、全部候選 ID 或大量相同的 excluded 理由不能結案。須使用 `review_queue.py --detail-id <規則ID>` 取得控制責任，再由來源追查 Controller／Handler／Service／Repository、Middleware、DI、設定與可能旁路；外部控制不應虛構程式碼鏈。詳見 [完整性守門操作指引](review-integrity-guards.md)。

## 完成 Fail／Review 前確認控制有效性

新版索引除對 Pass 驗證控制及繞過路徑外，對程式碼型 Fail 要求具體失效來源、攻擊情境與正式 Finding 一致；對已完成靜態查核的 Review 要求完整必要情境與真實外部裁決工件連結。使用既有 `control_verifications` 工作紀錄與 `review_safety.py` 暫存／整合流程，不會直接改動 `assessment.json` 判定。詳見 [安全控制有效性指引](control-effectiveness-review.md)。

## Review 判定品質要求

新增的審查索引要求每筆 `completed + review` 外部缺口具有真正可取得的工件、責任單位、互斥且會改變最終結果的兩種判定分支；組織政策類別需有已知政策識別及適用依據，不能使用制式的 `AC-01-deployment-or-policy-evidence`。無法完成靜態查核時保留 `pending/blocked`；已證實缺陷直接 `fail`＋Finding。詳見 [待確認判定指引](review-decision-adjudication.md)。

## 70 項執行迴圈

Agent 以安裝目錄中的 Python 腳本進行排程（下列為 Agent 內部指令，非一般使用者必須手動執行的步驟）：

```bash
sh "<SKILL_ROOT>/scripts/run-python.sh" "<SKILL_ROOT>/scripts/review_queue.py" --target "<TARGET_ROOT>" --init --batch-size 10 --compact
```

Windows PowerShell 對應指令：

```powershell
& "<SKILL_ROOT>\scripts\run-python.cmd" "<SKILL_ROOT>\scripts\review_queue.py" --target "<TARGET_ROOT>" --init --batch-size 10 --compact
```

首次執行可先用 `sh "<SKILL_ROOT>/scripts/run-python.sh" --check`（Windows：`& "<SKILL_ROOT>\scripts\run-python.cmd" --check`）唯讀檢查 Python 3.10+ 和相依套件。啟動器也檢查虛擬環境與常見 Windows 安裝位置；`--resolve` 取得已驗證的絕對路徑，設為 `SECURITY_CODE_REVIEW_PYTHON_PINNED` 固定當次審查。缺套件／不可呼叫時只診斷、不自動安裝。

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
sh scripts/run-python.sh scripts/validate_package.py
PYTHON="$(sh scripts/run-python.sh --resolve)"
"$PYTHON" -m unittest discover -s tests -v
```

核心檔案包括 `rules.json`、`rules.yaml`、`rules/`、`schemas/`、`templates/security-report.html` 及 `scripts/`。規則集 v2.0.0 的正式發布**不需公司資安簽核**；個別專案的實際法規適用、風險接受與制度文件，仍須依其權責與證據確認。


### 已存在 Finding 的證據更正

已確認 Finding 的來源行號或敘述經重查不正確時，**不可**直接覆寫或刪除。取得明確授權後，依 [受控更正契約](review-integrity-guards.md#已確認-finding-的受控更正不可直接編輯-assessmentjson) 在暫存 JSON 放入完整同 ID Finding 與 `finding_revisions` 原因／覆核者，執行 `--integrate --allow-revision --allow-finding-revision`。既有 confirmed、規則關聯與嚴重度底線保持；修訂前全文及前後雜湊寫入 assessment.finding_amendments，由現有 Manifest／Journal 保護。


### Block 後的合法續跑（不放寬守門）

- 第一輪尚未 70/70：可唯讀執行 `review_queue.py --diagnose-first-pass` 與 `--repair-plan`，同時查看 `pending_rule_ids`、`missing_source_paths` 與已完成規則的 blocker；僅修正真實缺失的檔案或規則，已完成判定需要明確授權才能 `--allow-revision`。
- `stalled`：允許唯讀 `--diagnose-first-pass`、`--repair-plan`、`--detail-id` 或 `review_safety.py --plan`；修改與整合仍維持退出碼 3。查明真正原因後使用 `review_log.py --target "<TARGET_ROOT>" start` 明確開新 run，續用舊審查證據，不重設 Finding。
- 自訂方法名稱的真實控制被 Regex 拒絕：依 [逐檔語意證據](file-review-contract.md) 的 `semantic_review` 記錄已人工核實之呼叫鏈、控制效果與正式來源行號；禁止以空泛解釋免除真實程式碼與繞過查核。
- Manifest／Journal 缺失或未提交、SHA256／Git 變動：先查 `evidence_integrity` 與 `snapshot_errors`，依法採用 `--recover-integrity` 或 `--snapshot-refresh` 並重新核對來源；未確定原證據完整性時不得刪除 Manifest、刷新可信鏈或直接寫 assessment。
- 本輪規則均 completed 但不能第二輪：`--diagnose-first-pass` 必須先完全通過；第二輪本身尚未完成不能當作第一輪缺失。只有第二輪 70 項完成後才執行正式 `--validate` 與報告交付。


## 實驗性基準觀測、執行事件與安全邊界

正式 B0 工具：`scripts/b0_baseline.py --latest <logs/latest.json> --output <b0.json>`。由於 `latest.json` 中 0 Token 可能表示未回報，這類值一律顯示為 `unavailable`。

P4-A 事件驗證：`scripts/execution_boundary_events.py --target <TARGET_ROOT> --run-id <RUN_ID> --verify`。JSON Schema 未知版本拒收。Agent 不具可信人工覆核權限；不得自行填入 `execution_boundary_review` 使 `pending_review` 通過。

執行邊界前置：`scripts/execution_boundary.py --target <TARGET_ROOT> --begin` 必須在 Log start 後呼叫，且同一 Run 不能覆寫原始基準。新版交易要在執行環境明確設定 `SECURITY_CODE_REVIEW_EXECUTION_MODE=optimized`；既有預設 legacy 續跑方式不受影響。L3 僅事後偵測 `analysis/` 可辨識的腳本變動；無可信完整能力清單時，禁止宣稱達成 L2。

新程式不得在 `analysis/` 臨時建立 `.py`、`.sh` 或 `.js` 修復器；既有舊腳本僅保留並等待可信的依賴審核，不直接刪除。其餘正式來源查核、Manifest／Journal 與第二輪完整性守門不變。


## 增量補查、收斂診斷與灰度／端到端驗收

選用的增量查核只規畫受影響範圍，不會自行標記正式 Pass 或准許進入第二輪；收斂診斷記錄 Blocker 指紋及有限策略，不以重試次數停止整個 Skill。小型專案灰度與 E2E 都需要真實工件才能通過，詳細命令及安全限制見 [增量驗證及正式驗收](incremental-convergence-acceptance.md)。
