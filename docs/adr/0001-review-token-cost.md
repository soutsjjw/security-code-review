# ADR 0001：降低審查 Token 成本的架構調整

- 狀態：已接受（2026-11-07）
- 範圍：完整審查（含多代理）、分類審查的執行方式；不改變規則、證據標準與報告格式

## 背景

掃描其他專案時，額度消耗明顯過快。以 `scripts/transcript_usage.py` 讀取 Claude Code 對話紀錄（依 message id 去重），CleanArchitecture.Northwind 4 次完整審查的實際用量如下：

| Session | API 呼叫 | Cache 讀取 | 輸出 | 最大 context | 平均 context | 子代理 | CodeGraph 查詢 |
|---|---|---|---|---|---|---|---|
| 40df2f39 | 177 | 88.4M | 235K | 761K | 504K | 0 | 0 |
| 68ea1bf3 | 281 | 114.3M | 519K | 952K | 413K | 0 | 0 |
| 6fd54499 | 300 | 129.8M | 560K | 960K | 437K | 0 | 0 |
| e1bcf6ce | 298 | 124.0M | 447K | 950K | 422K | 0 | 0 |

階段分佈（以 6fd54499 為例）：讀原始碼 131 次呼叫／55.1M cache 讀取；撰寫證據與暫存檔 108 次／50.4M，並占輸出的約 73%；Skill 腳本本身合計不到 15%。

觀察：

1. **成本來自 context 持續累積乘上呼叫次數。** 每次呼叫平均重讀 40 萬以上 tokens，後段逼近 1M。規則 guidance（每條約 6K 字元、其中約 2.2K 為 70 條共用的重複內容）、必讀文件（約 170K 字元）與讀過的原始碼一旦進入主 context，之後每次呼叫都會再付費。
2. **所有審查都在單一主 context 內完成，沒有任何子代理紀錄，也沒有執行 `multi_agent.py`。** 多代理文件以 Codex 的 `spawn_agent` 為準，Claude Code 執行時沒有對應的派工指引。
3. **CodeGraph 被偵測為可用（`structure-index.json` 的 `codegraph.available: true`），但 4 次審查皆未查詢。** 文件只寫「可用時優先使用」，沒有任何步驟或 gate 實際驅動它。
4. **輸出 Token 偏高**（每次 0.2～0.6M），主要來自代理手寫證據 JSON 與暫存腳本。

## 決策

### 目標與底線

- 主要目標：品質不變，降低總 Token。另提供明確標示的快篩模式。不設硬性 Token 上限（中途截斷會破壞證據閉合）。
- 不可犧牲：high tier 規則的第二輪驗證、證據閉合（行號＋SHA256）。standard tier 的重複驗證與抽樣比例可調整。
- 驗收：每項改動以 `quality_acceptance.py --compare` 比對。開發期間使用 Northwind 加 2～3 個代表案例；子代理架構與依範圍分流兩項合併前跑完整 16 案。

### 量測

- 以 Claude Code 對話紀錄的真實用量為準（`transcript_usage.py`），不再依賴人工輸入的 `token_metrics.py`。上表為 baseline。
- 量測同時檢查子代理紀錄數與 CodeGraph 查詢數；要求多代理卻沒有子代理紀錄，或 CodeGraph 可用卻從未查詢時發出警告。這是「假多代理」的事後防線；事前防線是派工指引明確要求使用 Agent 工具。不另做 nonce 之類的強制機制，因為它無法證明 context 隔離。

### 架構：協調者只保留精簡狀態

- 檔案批次或規則批次交給全新 context 的子代理處理，子代理只回傳結構化結果（verdict、行號、hash）。協調者不讀整份原始碼，也不讀完整 guidance。
- 協調者複核 finding 或排除理由時，只讀被引用的行號區間（約前後 20 行）並驗證 hash；不足以判斷時，再派新的 worker 深入檢查。
- `local` 規則依檔案批次派發；`cross_file`／`project` 規則每條（或同類小組）一個專屬 worker，沿呼叫鏈讀檔。
- 派發前由腳本對相關進入點執行 `codegraph explore`，結果附進 worker brief（上限約 8K 字元）；索引不存在或過期時改用 Roslyn 的 `cross_file_call_hints`。Roslyn 仍是 C# 跨檔呼叫點結案 gate 的正式依據；CodeGraph 只負責導航，不列入 gate，也不作為證據。
- Worker 不讀 `SKILL.md` 與完整文件。由腳本為每個批次產生精簡 brief（目標 15K 字元以內）：適用規則的精簡 guidance（共用部分只送一次）、結果 schema、輸出格式。完整標準文件只在判斷不確定時按需讀取。`--detail-id` 改為可一次查詢整批規則。
- Worker 先沿用與協調者相同的模型；降級為較便宜模型列為之後的獨立實驗。
- 執行器沒有子代理能力時，明確告知使用者，並建議改用 `--categories` 拆成多個獨立 session，不在同一個 context 內模擬多代理。

### 預設模式與快篩

- 執行器支援子代理且專案超過門檻時，完整審查預設走子代理架構；小專案維持單代理。門檻以量測資料決定。
- 快篩：第一輪 70 項由 worker 完成，第二輪只複核 high tier 與有 finding 的規則。報告標示「快篩，非完整審查」，不設 `ready_for_report`，不可作為品質驗收案例。

### 暫緩

- 輸出 Token 優化：等量測把輸出歸到更細的階段後再決定。
- Worker 模型降級：在量測與品質比對機制完成後，作為單一變數實驗。

## 交付順序

1. 量測腳本與 baseline（本 ADR 同批交付）
2. 精簡 worker brief、共用 guidance 只送一次、`--detail-id` 批次查詢
3. 子代理派發與協調者瘦身（含 Claude Code 的 Agent 工具派工指引）
4. 依 `review_scope` 分流派發與 CodeGraph 預查
5. 預設模式切換與快篩模式
6. 輸出優化與模型降級實驗

## 影響

- 好處：主 context 可望從平均 40 萬以上 tokens 降到數萬；長 context 造成的注意力下降與自動壓縮遺失證據的風險也隨之降低。
- 風險：跨檔推理受批次切割影響（以範圍分流與呼叫鏈預查緩解）；worker 編造證據（以 hash 驗證與協調者讀取引用區間緩解）；判斷標準不一致（共用 brief 與第二輪交叉複核緩解）。
- 成本：完整品質驗收需要 16 次完整審查，開發期間改用小樣本比對。
