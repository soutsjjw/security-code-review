# 模型對照實驗：同一版 Skill 換模型是否仍維持品質

此流程回答一個問題：**把主代理換成較便宜的模型（例如 Opus 5.5 → Sonnet 5.5），漏報與誤報會不會變多，又能省下多少 Token。** 它是 [ADR 0001](adr/0001-review-token-cost.md) 第 6 項「模型降級實驗」的操作步驟，只使用既有工具，不新增腳本，也不改變規則、證據標準或報告格式。

以下以 Windows PowerShell 為例，並用下列名稱：

| 名稱 | 意思 | 範例 |
|---|---|---|
| 基準模型 | 目前使用、品質已知的模型 | Opus 5.5（`claude-opus-5-5`），資料夾名 `opus` |
| 候選模型 | 想改用、比較便宜的模型 | Sonnet 5.5（`claude-sonnet-5-5`），資料夾名 `sonnet` |
| 案例 | `quality_baseline.py` 產生的 16 個小型 .NET 8 專案，每個都有已知的正確答案 | `di-strict-guard` |

## 整體流程

1. 準備：記錄實驗條件，產生兩份案例。
2. 試跑：兩個模型各審查同樣 5 個案例，共 10 次審查，再比對結果。
3. 如果候選模型在試跑中就表現較差，實驗到此結束；兩者相同，再補跑其餘 11 案，共 22 次審查。
4. 用正式驗收工具比較兩個模型，再比較成本，下結論。

每一次「審查」都是：在一個案例資料夾開一個**全新**的 Claude Code session，執行 `/security-code-review`，等它產出報告。

## 原則

- **一次只改一個變數**：兩組只差模型。Skill 版本、Claude Code 版本、effort、Fast mode 和審查模式都要相同，否則看到的差異無法歸因於模型。
- **品質優先於成本**：候選模型只要在任何一個案例退步，就不能用其他案例的進步或 Token 節省抵銷（沿用 [quality-acceptance.md](quality-acceptance.md#與前一版正式實測比較) 的規則）。
- **只採用實測數字**：Token 取自 Claude Code 的對話紀錄；沒跑完的案例就是沒跑完，不可依預期答案補填。
- **一個案例一個 session**：不同案例、不同模型都不能共用對話，以免結論與 context 互相污染。
- **不要給模型提示**：不要告訴 Claude 這是測試案例、預期結果是什麼，也不要替它判斷；只依 Skill 正常操作。

---

## 步驟 1：記錄實驗條件

開一個 PowerShell 視窗，先設定兩個路徑變數；之後每次開新的 PowerShell 視窗都要重新設定：

```powershell
$Skill = "$HOME\.agents\skills\security-code-review"
$Work  = "C:\model-test"
```

`$Work` 是實驗工作目錄，**不要放在任何 Git 儲存庫裡面**（包括 Skill 儲存庫）。否則 Skill 會把那個儲存庫的根目錄當成受測專案。

確認 Skill 工作樹是乾淨的，並記下版本：

```powershell
git -C $Skill status --short
git -C $Skill rev-parse HEAD
claude --version
```

第一個指令沒有任何輸出才算乾淨。把後兩個指令的結果，連同下表內容，記在你自己的實驗紀錄中：

| 項目 | 基準組 | 候選組 |
|---|---|---|
| Skill Git 版本 | （上面的 commit） | 必須相同 |
| Claude Code 版本 | （上面的版本） | 必須相同 |
| 模型 ID | `claude-opus-5-5` | `claude-sonnet-5-5` |
| effort | `high` | `high` |
| Fast mode | 關閉 | 關閉 |
| 審查模式 | 單代理（不加 `--multi-agent`） | 單代理 |

實驗進行中不要更新 Skill 或 Claude Code；更新了就要從頭再跑。

## 步驟 2：產生兩份案例

```powershell
python "$Skill\scripts\quality_baseline.py" --materialize "$Work\opus"
python "$Skill\scripts\quality_baseline.py" --materialize "$Work\sonnet"
```

每個指令會建立 16 個子資料夾，例如 `C:\model-test\opus\di-strict-guard\`，裡面有 `Case.csproj` 與幾個 `.cs` 檔。兩份內容相同；分開存放，兩個模型的報告才不會互相覆蓋。確認數量：

```powershell
(Get-ChildItem "$Work\opus" -Directory).Count     # 應為 16
(Get-ChildItem "$Work\sonnet" -Directory).Count   # 應為 16
```

再建立一份成本紀錄表，之後每審查完一個案例就填一列（可以用 Excel 開啟編輯）：

```powershell
"case,model,session_id,completed,api_calls,cache_read,output,first_pass_output,second_pass_output,cli_errors,manual_interventions,notes" |
  Set-Content "$Work\cost-log.csv" -Encoding utf8
```

## 步驟 3：審查一個案例（每次審查都照這個做）

以「用 Opus 審查 `di-strict-guard`」為例。

### 3-1 開新的 session

**Claude 桌面 App：**
1. 開一個新的 Code session。
2. 工作資料夾選 `C:\model-test\opus\di-strict-guard`，**一定要選案例資料夾本身**，不要選 `C:\model-test` 或 `opus`。
3. 在模型選擇器選 Opus 5.5，並確認 effort 與 Fast mode 符合步驟 1 的設定。

**或使用終端機的 Claude Code：**

```powershell
cd "$Work\opus\di-strict-guard"
claude --model claude-opus-5-5
```

工作資料夾必須是案例資料夾，原因是步驟 4 的 `transcript_usage.py` 會依這個路徑找到這次的對話紀錄。

### 3-2 開始審查

在新 session 中只輸入：

```text
/security-code-review
```

Claude 會自己執行所有 Python 指令，你不需要手動執行。過程中會跳出許多權限詢問：

- 請選「允許這一次」或「本次 session 允許」，**不要選「此專案永遠允許」**。後者會在案例資料夾建立 `.claude\settings.local.json`，驗收工具會把它當成「不屬於原案例的額外來源」而判定失敗。
- 如果還是產生了 `.claude` 資料夾，在步驟 6 驗收前刪掉它（它不是案例原始碼）。

### 3-3 中途停下來怎麼辦

審查應該一路做到產出報告。如果 Claude 中途停下來問「要不要繼續」，或因為錯誤停住：

- 在**同一個 session** 回覆「繼續」，不要另開 session。
- 每介入一次，就在紀錄表的 `manual_interventions` 加 1，並在 `notes` 簡短說明原因。
- 不要提示判定方向，例如「這裡應該是 fail」。

### 3-4 確認完成

Claude 回報完成並給出 HTML／JSON 報告路徑後，在 PowerShell 確認報告檔真的存在：

```powershell
$Case = "$Work\opus\di-strict-guard"
Test-Path "$Case\reports\security-code-review\assessment.json"   # 應為 True
Test-Path "$Case\reports\security-code-review\report.json"       # 應為 True
Get-ChildItem "$Case\reports\security-code-review\*.html"         # 應列出 HTML 報告
```

三項都存在才算完成，紀錄表的 `completed` 填 `yes`。如果放棄或無法完成，填 `no` 並在 `notes` 寫原因；**不要**自己補檔案。

## 步驟 4：記錄這次審查的成本

每完成一個案例就立刻記錄，比事後補記可靠。延續上一步的 `$Case`：

```powershell
# 這次審查的總用量（session id、API 呼叫數、cache 讀取、輸出）
python "$Skill\scripts\transcript_usage.py" --target $Case

# 依審查階段拆分（第一輪、第二輪、收尾各占多少）
python "$Skill\scripts\transcript_usage.py" --target $Case --run-log latest

# 審查中被 Skill 腳本拒絕（非 0 退出碼）的次數
(Select-String -Path "$Case\reports\security-code-review\logs\*.jsonl" -Pattern '"outcome":\s*"error"').Count
```

第一個指令的輸出類似：

```text
1a2b3c4d calls=210 cache_read=80.5M cache_write=1.20M output=310K max_ctx=620K mean_ctx=380K ...
```

把 session id（開頭 8 碼即可）、`calls`、`cache_read`、`output` 填進紀錄表。第二個指令在 `review phases` 底下會列出 `setup_and_first_pass` 與 `second_pass` 的 `output`，分別填進 `first_pass_output`、`second_pass_output`。第三個指令的數字填進 `cli_errors`。

說明：

- `--run-log latest` 只統計最後一個執行回合。若審查中斷又續跑過，總用量以第一個指令為準。
- `cli_errors` 包含守門拒絕寫入、指令參數錯誤等，是「模型多常需要重做」的近似指標，用來比較兩個模型，不代表每一次都是品質問題。
- `transcript_usage.py` 不會記錄模型，所以紀錄表的 `model` 欄要自己填。

## 步驟 5：試跑 5 個案例

16 案 × 2 個模型要跑 32 次完整審查，成本很高。先用最能區分模型能力的 5 個案例試跑：

| 案例 | 為什麼選它 |
|---|---|
| `di-strict-guard`／`di-permit-all-guard` | 要追 DI 實際綁定，跨檔推理最難 |
| `config-production-expiry`／`config-production-disables-expiry` | 要追組態覆寫，容易只看程式碼就下結論 |
| `recovery-drill-external` | 外部證據案例，測試模型會不會捏造程式碼鏈 |

前四個是成對案例（一個安全、一個有弱點），所以能同時測出漏報與誤報。

對 `opus` 與 `sonnet` 兩個資料夾裡的這 5 個案例，各照步驟 3、4 做一次，共 10 個 session。

全部完成後，對兩個工作目錄執行評分：

```powershell
python "$Skill\scripts\quality_baseline.py" --assessments "$Work\opus"   --output "$Work\pilot-opus.json"
python "$Skill\scripts\quality_baseline.py" --assessments "$Work\sonnet" --output "$Work\pilot-sonnet.json"
```

評分器會把 16 案都列出來，沒跑的 11 案顯示為未完成，因此試跑時的退出碼一定是 1，總分也沒有意義。**只看這 5 案：**

```powershell
$Pilot = "di-strict-guard","di-permit-all-guard","config-production-expiry","config-production-disables-expiry","recovery-drill-external"
foreach ($m in "opus","sonnet") {
  "== $m =="
  (Get-Content "$Work\pilot-$m.json" -Raw -Encoding utf8 | ConvertFrom-Json).cases |
    Where-Object case_id -in $Pilot |
    Format-Table case_id, expected, actual, status_match, evidence_valid, passed
}
```

各欄位意思：

| 欄位 | 意思 |
|---|---|
| `expected` | 正確答案（`pass`／`fail`／`review`） |
| `actual` | 模型的判定 |
| `status_match` | 判定是否正確 |
| `evidence_valid` | 引用的程式碼證據是否有效 |
| `passed` | 判定、Finding、跨檔追查與證據全部正確 |

**判讀：**

- 候選模型有任何一案 `passed` 是 `False`，而基準模型同一案是 `True`：候選模型退步。實驗可以結束，結論是「不適合當主代理」。
- 兩個模型在同一案都是 `False`：問題可能在 Skill 本身，不是模型差異，應另外追查。
- 5 案結果相同：比較紀錄表的成本。候選模型明顯比較便宜才值得進入步驟 6；不然也不必繼續。

## 步驟 6：完整 16 案與正式比較

照步驟 3、4 補跑其餘 11 案，兩個模型都要跑。完成後先確認案例資料夾裡沒有多出來的設定檔，有就刪除：

```powershell
Get-ChildItem "$Work\opus","$Work\sonnet" -Directory -Recurse -Force -Filter ".claude"
```

然後執行正式驗收：

```powershell
python "$Skill\scripts\quality_acceptance.py" --workspace "$Work\opus" --output "$Work\quality-opus.json"
python "$Skill\scripts\quality_acceptance.py" --workspace "$Work\sonnet" --compare "$Work\quality-opus.json" --output "$Work\quality-sonnet.json"
```

第二個指令以 Opus 的結果作為比較基準，所以 Sonnet 相對於 Opus 的退步會列在輸出的 `regressions`。查看結果：

```powershell
$r = Get-Content "$Work\quality-sonnet.json" -Raw -Encoding utf8 | ConvertFrom-Json
$r.quality_gate_passed
$r.regressions
```

- 指令退出碼 `0`、`quality_gate_passed` 為 `True`、`regressions` 為空：候選模型在 16 案中沒有任何退步。
- 退出碼 `1`：有案例未完成、證據不全或退步，原因寫在輸出 JSON 中。
- 退出碼 `2`：路徑或輸入格式錯誤，通常是 `$Work` 設錯。

基準模型自己的驗收（第一個指令）也必須是 `quality_gate_passed=True`。如果基準模型本身就沒通過，比較的參考價值有限，應先處理基準模型失敗的案例。

## 步驟 7：比較成本並下結論

用 Excel 開啟 `C:\model-test\cost-log.csv`，依 `model` 分組加總 `cache_read`、`output` 與 `api_calls`，再乘上各模型當下的單價換算費用；文件不寫入價格，以免數字過時。同時比較 `cli_errors` 與 `manual_interventions`。較便宜的模型若常被退回重做，總用量可能反而更高。

候選模型要**同時**符合下列條件，才建議改用：

1. 步驟 6 兩個驗收都回傳退出碼 0，而且候選模型的 `regressions` 是空的。
2. 16 案全部完成，沒有需要人工救回才能完成的案例。
3. 換算後的總費用明顯低於基準模型，`cli_errors` 與 `manual_interventions` 沒有大幅增加。

## 注意事項

- **每個模型每案只跑一次，有隨機誤差。** 若兩組只在單一案例的判定不同，請對該案例各再跑一次（重新產生案例資料夾後再審查），確認差異可以重現再下結論。
- **16 案只代表這 16 案。** 它們都是小型 .NET 8 專案，真實專案的長 context 與跨專案推理更難。通過後，建議再對 Northwind 各跑一次完整審查，並以 `quality_gate.py --target ... --compare ...` 比較（見 [quality-acceptance.md](quality-acceptance.md#全-70-項品質契約覆蓋與真實專案驗收)）。
- **結果只適用於該 Skill 版本。** Skill 有大幅修改後，結論需要重新驗證。
- 實驗紀錄、驗收 JSON 與案例資料夾都放在 `$Work`，不要放進 Skill 儲存庫。本文件只描述流程，不存放實測結果。
