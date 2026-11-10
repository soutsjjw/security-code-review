# 模型對照實驗：同一版 Skill 換模型是否仍維持品質

此流程回答一個問題：**把主代理換成較便宜的模型（例如 Opus 5.5 → Sonnet 5.5），漏報與誤報會不會變多，又能省下多少 Token。** 它是 [ADR 0001](adr/0001-review-token-cost.md) 第 6 項「模型降級實驗」的操作步驟，只使用既有工具，不新增腳本，也不改變規則、證據標準或報告格式。

以下稱目前使用的模型為**基準模型**，要評估的模型為**候選模型**。

## 原則

- **一次只改一個變數**：兩組只差模型。Skill Git 版本、Claude Code 版本、effort、審查模式（單代理／多代理）、Fast mode 與必讀文件必須相同，否則差異無法歸因於模型。
- **品質優先於成本**：候選模型只要在任何一個案例退步，就不能用其他案例的進步或 Token 節省抵銷（沿用 [quality-acceptance.md](quality-acceptance.md#與前一版正式實測比較) 的規則）。
- **只採用實測數字**：Token 取自 Claude Code 對話紀錄；未完成的案例記為 missing，不可依預期答案補填。
- **每個案例都是全新的 session**：不同案例、不同模型不得共用同一個對話，避免互相污染結論與 context。

## 0. 記錄實驗條件

開始前先記錄下列條件，兩組必須一致（模型除外）：

| 項目 | 取得方式 |
|---|---|
| Skill Git 版本 | 在 Skill 根目錄執行 `git rev-parse HEAD`，工作樹須乾淨 |
| Claude Code 版本 | `claude --version` |
| 模型 ID | 例如 `claude-opus-5-5`／`claude-sonnet-5-5`；`transcript_usage.py` **不會**記錄模型，必須自行登記 |
| effort | 建議兩組都設為 `high` |
| Fast mode | 兩組都關閉（Fast mode 只影響速度，但會改變成本） |
| 審查模式 | 兩組都用預設單代理；若要比較多代理，另開一組實驗 |

## 1. 產生兩份隔離案例

每個模型各用一個空的工作目錄，路徑放在 Skill 儲存庫之外：

```bash
python "<SKILL_ROOT>/scripts/quality_baseline.py" --materialize "<WORK>/baseline-model"
python "<SKILL_ROOT>/scripts/quality_baseline.py" --materialize "<WORK>/candidate-model"
```

兩份案例的內容相同；分開存放，兩個模型產生的 `reports/` 才不會互相覆蓋。

## 2. 先做小樣本試跑（建議）

16 個案例 × 2 個模型要跑 32 次完整審查，成本很高。建議先用最能區分模型能力的 5 個案例試跑：

| 案例 | 為什麼選它 |
|---|---|
| `di-strict-guard`／`di-permit-all-guard` | 需要追 DI 實際綁定，跨檔推理最難 |
| `config-production-expiry`／`config-production-disables-expiry` | 需要追組態覆寫，容易只看程式碼就下結論 |
| `recovery-drill-external` | 外部證據案例，測試模型會不會捏造程式碼鏈 |

同時包含 pass 與 fail 的成對案例，才能同時測出漏報與誤報。

在每個案例的專案根目錄開新的 Claude Code session，用 `claude --model <模型 ID>` 或 App 的模型選擇器指定模型，然後執行完整 70 項審查（`$security-code-review`），直到 `ready_for_report=true` 並產生報告。中途被守門擋下而重做、被中斷或需要人工介入的次數，請登記在第 4 節的紀錄表。

試跑完成後，用評分器比對指定規則（缺少的案例會列為 missing，不會被當成通過）：

```bash
python "<SKILL_ROOT>/scripts/quality_baseline.py" --assessments "<WORK>/baseline-model" --output "<WORK>/pilot-baseline.json"
python "<SKILL_ROOT>/scripts/quality_baseline.py" --assessments "<WORK>/candidate-model" --output "<WORK>/pilot-candidate.json"
```

**若候選模型在試跑中就出現漏報、誤報，或無法完成審查，即可結束實驗，結論為「不適合當主代理」。** 只有試跑結果與基準模型相同，才值得跑完整 16 案。

## 3. 完整 16 案與正式比較

補跑其餘案例，讓兩個工作目錄都有 16 份完整審查，再分別執行正式驗收：

```bash
python "<SKILL_ROOT>/scripts/quality_acceptance.py" --workspace "<WORK>/baseline-model" --output "<WORK>/quality-baseline-model.json"
python "<SKILL_ROOT>/scripts/quality_acceptance.py" --workspace "<WORK>/candidate-model" --compare "<WORK>/quality-baseline-model.json" --output "<WORK>/quality-candidate-model.json"
```

第二個指令以基準模型的結果作為「前一版」，因此輸出中的 regression 就是**候選模型相對於基準模型的退步**，涵蓋已知弱點漏報、正常案例誤報、外部待確認判定、跨檔追查與證據有效性。

## 4. 量測成本

每個案例審查結束後，在該案例的專案根目錄統計這次審查的實際用量：

```bash
python "<SKILL_ROOT>/scripts/transcript_usage.py" --target "<CASE_ROOT>" --run-log latest --json
```

輸出會依審查執行 Log 把用量拆成 `setup_and_first_pass`、`second_pass`、`finalize` 等階段（說明見 [advanced-usage.md](advanced-usage.md#claude-code-對話紀錄-token-統計)）。不同模型的單價不同，請比較 Token 數量與 API 呼叫數，再自行乘上各模型的價格換算成本；文件不寫入價格，以免數字過時。

每個案例登記一列：

| 案例 | 模型 | session id | `ready_for_report` | 指定規則判定是否正確 | API 呼叫數 | cache 讀取 | 輸出 | 第一輪／第二輪輸出 | 守門退件重做次數 | 中斷或人工介入 |
|---|---|---|---|---|---|---|---|---|---|---|

「守門退件重做次數」最能反映模型是否穩定遵守協定：較便宜的模型若常被 `review_safety` 拒絕而重寫，單次呼叫雖然便宜，總 Token 仍可能更高。

## 5. 判讀與結論

候選模型要同時符合下列條件，才可以建議改用：

1. 兩組的 `quality_acceptance.py` 都回傳退出碼 0，且候選模型的 `--compare` 沒有任何 regression。
2. 16 個案例全部達到 `ready_for_report=true`，沒有需要人工救回的案例。
3. 總成本（Token × 單價）明顯低於基準模型；守門退件重做次數沒有大幅增加。

注意事項：

- **每個模型每案只跑一次，有隨機誤差。** 若兩組只在單一案例的判定不同，請對該案例各再跑一次，確認差異可以重現再下結論。
- **16 案只代表這 16 案。** 它們都是小型 .NET 8 專案，真實專案的長 context 與跨專案推理更難。通過後，建議再對 Northwind 各跑一次完整審查，並以 `quality_gate.py --target ... --compare ...` 比較（見 [quality-acceptance.md](quality-acceptance.md#全-70-項品質契約覆蓋與真實專案驗收)）。
- **結果只適用於該 Skill 版本。** Skill 有大幅修改後，結論需要重新驗證。
- 實驗紀錄、驗收 JSON 與 session id 請保存在 Skill 儲存庫之外；本文件只描述流程，不存放實測結果。
