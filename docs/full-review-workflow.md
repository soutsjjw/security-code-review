# 完整 70 項審查操作流程

僅適用**未指定 `--categories`** 的正式完整模式。Agent 在初始化正式佇列前必讀此文件，之後循本流程持續審查；每個階段還須按 `SKILL.md` 的載入表讀取對應細則。不得依預覽進度宣稱正式完成。

## 完整 70 項審查的執行 Log、效能量測與安全續跑

**正式完整模式必須啟用。** Agent 決定 TARGET_ROOT 後，先執行：

```bash
sh "<SKILL_ROOT>/scripts/run-python.sh" "<SKILL_ROOT>/scripts/review_log.py" --target "<TARGET_ROOT>" start
```

- 日誌固定保存於 `TARGET_ROOT/reports/security-code-review/logs/`：`<run_id>.jsonl`、`<run_id>-summary.json`、`latest.json`。每次啟動產生新 `run_id`，續跑保留 `review_id`；明確開始新的審查才加 `start --new-review`。
- `analysis_prepare.py`、`review_queue.py`、`review_safety.py`、`complete_review.py` 自動記錄 CLI 指令耗時及退出狀態。Agent **每批實際證據成功保存後**另記一次 checkpoint：

```bash
sh "<SKILL_ROOT>/scripts/run-python.sh" "<SKILL_ROOT>/scripts/review_log.py" --target "<TARGET_ROOT>" checkpoint --phase first_pass --completed-rules 12 --reviewed-files 80
sh "<SKILL_ROOT>/scripts/run-python.sh" "<SKILL_ROOT>/scripts/review_log.py" --target "<TARGET_ROOT>" checkpoint --phase cross_file_analysis --verified-callsites 25
sh "<SKILL_ROOT>/scripts/run-python.sh" "<SKILL_ROOT>/scripts/review_log.py" --target "<TARGET_ROOT>" checkpoint --phase second_pass --second-pass-rules 6
```

- 上述數字**只是示例**，必須用當次已儲存、可核對的真實累計值；Token 只在執行器提供實際數值時記錄。無執行器心跳時，checkpoint 只在 Agent 明確呼叫時更新，**不可聲稱背景自動監測**。
- 連續至少 4 次無進展且距上次進展至少 15 分鐘，checkpoint 設為 `stalled`、退出碼 3。Agent 必須保存已核對證據、列出卡住的規則／跨檔候選與下一個實際調查動作；不可重複空跑，也不可把 STALLED 改為 Pass。查明後再次 `start` 續跑，必要時 `finish --status blocked` 或 `finish --status interrupted`。
- `--compact` 與 `--detail-id` 是**未執行完整驗證的進度預覽**：`validation_deferred=true`、`ready_for_report=false`；`source_coverage.verified=false` 的檔案數僅供排序。規則及檔案全部完成後，必須執行**不帶 `--compact` / `--detail-id`** 的 `review_queue.py`、`review_safety.py --validate` 及正式報告驗證。不可用預覽值宣稱 100%。
- 首次結構分析使用 `--mode full`；來源快照未變且索引版本一致的續跑使用 `--mode incremental`，才重用 Roslyn 與跨檔索引。來源、規則或分析器版本異動，一律回到完整重新核對與原先的快照守門；快取永遠不代替程式碼證據。
- Log **不是安全證據或交易完整性紀錄**，不屬於 `assessment.json` 的受控交易；不記錄來源全文、密碼、Token、Prompt 或未過濾例外訊息。不可刪除舊 Finding、弱化 70 項／跨檔／第二輪／100% 來源驗證。完整報告成功驗證才自動記錄 `completed`。

## 技術支援及 Token 優化前置（必須執行）

本節技術支援範圍、證據及 Token 原則適用兩種模式；其中 `analysis_prepare.py`、不帶分類參數的佇列和正式 `analysis/` 只適用完整模式。分類模式改用上方 `review_queue.py --categories ... --prepare`。

- **本階段只接受 .NET Core／現代 .NET C# 專案（包含 `net10.0`）**。對直接且無條件的 `.csproj` TFM 採字面值；若使用父層 `Directory.Build.props`、`Directory.Build.targets`、明確 `<Import>` 或條件式屬性，必須以 `dotnet msbuild <csproj> -getProperty:TargetFramework,TargetFrameworks,TargetFrameworkVersion` 進行唯讀評估（不執行 Build／Restore），並核對全部專案。沒有可用的 MSBuild 17.8+、無法解析屬性、缺少相容 SDK 時仍須阻斷，不得猜測或修改受測專案。遇到 .NET Framework、Vue／混合專案、無法辨識的框架，暫停並明確說明尚未支援，**不得縮小覆蓋率後宣稱完成**。後續透過 `scripts/analysis_adapters.py` 的統一分析器介面擴充 .NET Framework／Vue；70 項規則和報告 Schema 保持共用。
- 在 Python 環境檢查成功後、開始審查佇列之前，由 Agent 在受測專案執行（首次 full；只有確實存在舊結構索引且要重新分析時才用 incremental）：

  ```bash
  sh "<SKILL_ROOT>/scripts/run-python.sh" "<SKILL_ROOT>/scripts/analysis_prepare.py" --target "<TARGET_ROOT>" --mode full
  ```

  Windows：`& "<SKILL_ROOT>\\scripts\\run-python.cmd" "<SKILL_ROOT>\\scripts\\analysis_prepare.py" --target "<TARGET_ROOT>" --mode full`。
- 此步驟唯讀盤點來源，將 Roslyn 產出的 C# 語法結構索引與 SHA256 保存到受測專案 `reports/security-code-review/analysis/structure-index.json`。Roslyn 由已安裝的 .NET SDK 8+ 提供（暫存目錄編譯，不變更受測專案、不自動安裝套件），不存在時降級為來源閱讀。**這只是符號／語法索引，不是 Roslyn 安全掃描或 SAST 結論**。
- 自動偵測 CodeGraph CLI 與既有 `.codegraph/` 索引；可用時優先以 `codegraph_explore` MCP 或 `codegraph explore` 查詢結構、方法與跨檔案呼叫鏈。失敗、未安裝、未索引或索引過期時使用原有來源讀取／搜尋，不得自行執行 `codegraph init`。CodeGraph 索引**不能取代程式碼、組態、資料流及測試證據**，來源異動後須確認索引新鮮度。
- 增量模式只重用**未改變的語法結構索引**，不是自動重用 `pass/completed`。當任何已盤點來源新增、修改、刪除時，未取得可驗證的完整跨檔案影響閉包前，保守重新檢核全部來源；保留原有 Findings，但須覆核受影響的既有判斷。
- 執行佇列優先 `--compact` 以節省回傳 Token；其結果只為未驗證進度預覽，不代表正式完整性守門通過；每處理一條規則須以 `review_queue.py --target "<TARGET_ROOT>" --detail-id <RULE_ID>` 按需取出該條的完整補充規範，不可因精簡佇列而略過適用的標準及步驟。整合同檔案的分析結果供多規則共用，但保留每個檔案的 10 類篩選、每條規則的個別理由與可定位真實證據。
- 僅在 Codex／Claude 等執行器可取得**實際 Token 數**時，使用 `scripts/token_metrics.py` 記錄 input/output/cached tokens 與工具呼叫數；不可臆測成本數字。結構索引、Token 統計與快取**不計入來源覆蓋，不寫入 assessment 的安全結論**。

## 可選受控多代理分工（僅完整模式）

使用者明確指定 `--multi-agent` 時，主代理於分析準備／初始化完成後依 [受控多代理實作契約](multi-agent-review.md) 完成 執行器能力試跑 實測核可、Worker Schema 驗證及分片派工。未通過 執行器能力試跑 或強制唯讀不足時退回單代理。子代理不得寫入正式 JSON 或宣告安全結果；
正式 70 項、100% 來源與第二輪驗證均不變。

## 自動審查流程（完整模式；未指定 `--categories`）

**完整模式（未指定 `--categories`）的交付物是 70 項正式資安審查報告；分類模式的交付物為各選定分類的部分審查報告，依上方分類流程另行驗證。**
單次執行須主動持續查核直到 70 項完成且 HTML／JSON 驗證通過；僅有真正無法繼續的環境／工具錯誤才停止。
不得因發現 1～3 項風險、完成少量來源查證、缺少外部部署資訊或看到仍有 pending 就結束並要求使用者再次呼叫 Skill。

### 必須執行的佇列迴圈（Codex／Claude Code）

1. 以 `SKILL_ROOT` 為腳本位置、`TARGET_ROOT` 為受測專案，**先檢查執行環境，再立即啟動佇列**。Agent 應判斷實際使用的 Shell，並先按上方規定解析、固定 Python：
   - macOS／Linux（Bash／sh）：
     ```bash
     sh "<SKILL_ROOT>/scripts/run-python.sh" --check
     sh "<SKILL_ROOT>/scripts/run-python.sh" "<SKILL_ROOT>/scripts/review_queue.py" --target "<TARGET_ROOT>" --init --batch-size 10 --compact
     ```
   - Windows（PowerShell）：
     ```powershell
     & "<SKILL_ROOT>\scripts\run-python.cmd" --check
     & "<SKILL_ROOT>\scripts\run-python.cmd" "<SKILL_ROOT>\scripts\review_queue.py" --target "<TARGET_ROOT>" --init --batch-size 10 --compact
     ```
   `--resolve` 與 `--check` 在開始時執行並固定同一支 Python。啟動器搜尋可用 Python 3.10+ 與 `requirements.txt` 套件；後續呼叫使用 `SECURITY_CODE_REVIEW_PYTHON_PINNED`，不得每次重新選版。此命令只在檔案不存在時建立 70 項 pending 草稿；已存在的 assessment.json、findings、project.json 一律保留。**pending 是待執行工作清單，不是完成結果**。
2. 使用工具輸出的 `next_checks`、`search_targets`，並依 `--detail-id` 取得 `decision_guidance`、`control_effectiveness_guidance`、`decision_adjudication_guidance`、`inspection_hints` 和適用條件，在 `TARGET_ROOT` **逐條真正查核**該批規則：搜尋只用於定位候選，必須實際閱讀程式碼、確認呼叫鏈、追蹤資料流及安全控制實作，檢查可能的繞過／攻擊路徑，逐條記錄來源檔行號（或可識別的外部工件）、方法、證據及判定理由。找到疑似弱點就直接建立 `assessment.findings[]`，並正確關聯 `check_ids`／`finding_ids`；**不修改程式、不要求先修復、不停止迴圈**。已查核且本規則必要的部署、政策或動態證據確實無法取代時可記為 `status=review`、`execution.state=completed`，但需具體紀錄哪些部分已查核、哪些資訊缺少。
3. **每完成一項／每批立即保存**：先將單檔／規則結果透過 `review_safety.py --stage` 獨立暫存，再用 `--integrate` 無衝突整合到 `TARGET_ROOT/reports/security-code-review/assessment.json`；已有 Finding 必須保留。跨檔／全專案規則未結案時保持 `pending`，不得提前填為 `completed`。然後再次執行佇列（不必重新初始化）。
4. 尚有 pending 或逐檔待修復項目時回到步驟 2。每批可唯讀執行 `--diagnose-first-pass` 與 `--repair-plan`，及早發現已完成規則證據的錯誤。未完成項目不能視為已通過。
5. 第一輪 70 項完成且 `--diagnose-first-pass` 回傳 `ready_for_second_pass=true` 後，才能 `--begin-second-pass`。第二輪逐條完成後，才執行正式 `review_safety.py --validate` 與不帶 `--compact` 的佇列，要求 `ready_for_report=true`。正式驗證不可變成第二輪前的通關條件。
6. 由 Agent 內部呼叫 `complete_review.py`，產出最終 `CodeReview_YYYYMMDD.html`、`report.json` 並驗證。最終答覆優先交付這兩個路徑、70 項狀態摘要與 Finding 數；改善建議應收錄於報告中，不要在最終訊息中先要求修復。

**注意**：`review_queue.py` 只負責初始化、呈現下一批規則及進度計數，不會自行完成原始碼的 70 項判斷。Agent 必須實際使用程式碼／設定證據逐項分析；不得把佇列已列出 70 個 ID 當作審查完成。
