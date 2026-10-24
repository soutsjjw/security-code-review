# P0：資安審查正確性基準（單代理）

此基準是後續 P1～P6 的**已知答案對照**，不修改 70 項規則、判定矩陣、assessment Schema 或 HTML／JSON 報告。案例刻意包含不安全程式碼，**僅供隔離測試，禁止部署**。

## 基準內容

`tests/fixtures/p0-quality-baseline/cases.json` 有 16 個隔離案例：

| 領域 | 規則 | 對照 |
|---|---|---|
| Session 到期 | AC-01 | 正常拒絕逾期／忽略到期 |
| 物件層級授權（Controller → Handler → Service → Repository） | AC-08 | 驗證 owner／只依物件 ID |
| SQL Injection（Controller → Handler → Repository） | IN-01 | 參數化／字串串接 |
| 密碼雜湊 | AU-08 | 隨機 salt + PBKDF2／未加鹽 SHA256 |
| DI 實際綁定 | AC-08 | 嚴格授權實作／允許所有人 |
| Middleware 與端點授權 | AC-08 | RequireAuthorization／AllowAnonymous |
| Production 設定覆寫 | AC-01 | 正常逾時／覆寫成無效並降級成一年 |
| 備援啟動演練 | BC-07 | 缺正式演練紀錄，預期 review |
| 實際高可用部署 | BC-03 | 只有副本宣告，缺實際拓撲，預期 review |

其中 7 組 pass／fail 成對案例，加上 2 個確實涉及儲存庫外證據的 review 案例。每筆記錄包含真實來源、規則 ID、預期結論、Finding 期望、必查來源路徑、參考錨點、核定理由；錨點不是唯一合法證據位置。

**重要邊界**：標籤只判定該案例指定的**單一控制／規則**；不是對整個示例專案的 70 項規則全面宣稱 pass，也不能由基準資料反填真實審查結論。對照結果不等於已證明 Agent 能找出這些弱點。

## 1. 驗證案例與評分器本身

在 Skill 儲存庫根目錄執行：

```bash
python -m unittest discover -s tests -p "test_quality_baseline.py" -v
python -m unittest discover -s tests -v
python scripts/validate_package.py
```

單元測試涵蓋案例標籤一致性、來源錨點、路徑安全、已知弱點漏報／誤報、遺漏案例、無效證據、Finding 對帳，以及評分器 CLI 的失敗退出碼。CI 的完整測試流程會一併執行。

## 2. 產生隔離測試專案

```bash
python scripts/quality_baseline.py --materialize /tmp/security-review-p0
```

每個案例會產生一個獨立的 `net8.0` 專案，並帶有該案例自己的來源。要求目標資料夾不存在或為空，以免覆蓋報告。產生後不自動執行資安審查，也不修改案例原始碼。

逐個案例在對應的專案根目錄執行現有 `$security-code-review`（或指定該專案路徑），讓 Skill 真正產生 `reports/security-code-review/assessment.json`。**各案例必須隔離審查**，否則一個案例的 fail 會污染另一個安全對照的結論。

> 如果執行資源不足，先保留未完成案例為 missing，不可人工填入預期值冒充實際結果。

## 3. 從真實 assessment.json 比對

```bash
python scripts/quality_baseline.py --assessments /tmp/security-review-p0 --output p0-results.json
```

評分器會從每個案例的 70 項檢核中，取出**指定規則**的 `status`、Finding、`inspected_paths` 和來源證據行號；缺少 assessment、尚未 `completed` 的規則或缺少來源證據的案例不會被當成通過；只有實際存在的 Finding 才算有效。

也可以比對事先擷取的預測資料：

```bash
python scripts/quality_baseline.py --evaluate predictions.json --output p0-results.json
```

格式：

```json
{
  "cases": [
    {
      "case_id": "session-expiry-bypass",
      "status": "fail",
      "finding": true,
      "inspected_paths": ["SessionRecord.cs", "SessionValidator.cs"],
      "evidence": [
        {"path": "SessionValidator.cs", "line_start": 4, "line_end": 4}
      ]
    }
  ]
}
```

以上僅是**輸入格式示例**，不得當成真實 Agent 的審查成果。

## 4. 品質驗收與限制

評分器輸出包含：

- `status_accuracy`：已知案例規則狀態正確率（遺漏計錯）。
- `fail_recall`／`missed_fail`：已知弱點的召回率／漏報數。
- `fail_precision`／`false_positive_fail`：已知案例中 fail 的精確率／誤報數。
- `review_correct`：預期外部待確認案例判定正確數。
- `review_gap_specific_count`：預期 review 必須在「待確認：」後指出相符的外部工件關鍵詞；其他同義工件仍需人工複核，避免制式缺測試理由被放行。
- `trace_complete_count`：每案例要求追查的來源檔是否均已列入 `inspected_paths`。
- `evidence_valid_count`：來源證據路徑與行號是否有效。
- `anchor_cited`：是否引用已知參考錨點，僅供參考，**不強制把其他合法來源證據判錯**。

`all_passed` 須所有案例狀態、Finding、追查路徑及可定位證據均符合基準；不符合時 CLI 退出碼為 1；輸入不合法時為 2。這些量測是**有限的回歸基準**，不能推論任意專案的真實漏報率，也不取代人工複核。

**P0 交付界線**：建立並驗證案例與評分器，不執行耗用大量 Agent 工作階段的 16 次完整審查。正式測出當前單代理的召回／誤報基線後，才有可比較的 P1～P6 品質數據。未實際執行時不得寫成「基線 100% 正確」。

**後續 P1～P6 驗收原則**：版本與案例相同，優先確保重大／高風險已知案例零漏報，且不能增加無依據誤報；規則結果與證據必須同時通過，不能以 Token 減少交換正確性。

## 固定案例的正式版本驗收

評分器的 `--evaluate` 只檢查資料結構與評分契約，**不是**真實審查成果。要驗收新版 Skill 的 Agent 品質，請依 [真實審查品質驗收](quality-acceptance.md) 先對全部 16 個隔離專案取得完整 70 項與正式報告，再執行 `quality_acceptance.py --workspace`；跨版本比較使用 `--compare`。未取得全部工件不得宣稱 16/16 或零漏報。
