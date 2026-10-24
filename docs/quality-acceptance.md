# 真實審查品質驗收與跨版本回歸比較

此功能用於**完成 Skill 正式審查後**，對固定 16 個隔離案例的 `assessment.json`、Finding、來源證據與 HTML／JSON 報告執行品質驗收。它不會呼叫 AI、不會產生安全判定，也不能以預期答案填入審查結果。

## 驗收資料

固定題庫為 `tests/fixtures/p0-quality-baseline/cases.json`：7 組安全／不安全對照、2 項真實外部待確認控制。由 `quality_baseline.py` 生成 16 個獨立 .NET 8 專案：

```bash
python "<SKILL_ROOT>/scripts/quality_baseline.py" --materialize "<EMPTY_CASE_WORKSPACE>"
```

由**同一版 Skill 與明確記錄的模型／執行器**對每個案例分別執行完整 70 項、100% 來源覆蓋、跨檔及控制有效性分析、待確認判定與第二輪反向複核，最後執行 `complete_review.py` 產生實際的 `assessment.json`、`report.json` 及同日期 HTML。案例程式碼只能用來測試，嚴禁部署。

每個案例應保留執行日誌、模型設定、Git 版本與可用時的實際 Token 使用紀錄；審查報告和評分工具**不能單獨證明**模型確實閱讀程式碼，需人工稽核執行過程。工具不自行啟動 16 次代理工作階段。

## 執行正式品質驗收

```bash
python "<SKILL_ROOT>/scripts/quality_acceptance.py" --workspace "<CASE_WORKSPACE>" --output "<QUALITY_RESULT>.json"
```

嚴格要求每個案例：
- 原始碼與固定題庫逐位元組一致，沒有額外 `.cs`／設定檔改變實際攻擊面。
- 存在完整 70 項 `completed` 的 `assessment.json`，且使用正式佇列 `ready_for_report=true`：所有現有來源覆蓋、Finding、證據、工作中控制及第二輪完整性守門都通過。
- 存在正式 `report.json` 與對應審查日期的 HTML。
- 目標規則的狀態、Finding、跨檔 `inspected_paths`、真實來源行號及必要外部 `review` 工件均符合案例的人工預期。

輸出 `measurement_source=review_artifacts`、固定題庫 SHA256、16 個案例的工件驗證結果與原始 P0 評分器各項度量。案例缺席、分析未完成或任何證據守門不合格都視為**未通過**，不是合格或可忽略。若全部驗證通過且已知弱點漏報／誤報皆為 0，則 `quality_gate_passed=true`。

**CI 的合成測試只能驗證這個驗收工具是否正確阻擋錯誤資料，不代表模型的漏洞發現率、誤報率或效率已實測改善。**

## 與前一版正式實測比較

```bash
python "<SKILL_ROOT>/scripts/quality_acceptance.py" --workspace "<NEW_CASE_WORKSPACE>" --compare "<PREVIOUS_QUALITY_RESULT>.json" --output "<NEW_QUALITY_RESULT>.json"
```

僅接受相同題庫 SHA256、相同驗收格式且標示為 `review_artifacts` 的前一版結果。比較以下變化：已知弱點漏報數、正常案例誤報數、整體判定正確數、完整通過案例、外部待確認正確數及具體工件理由、跨檔追查及證據有效數。**任何先前已通過的單一案例退步都不能用其他案例的改善抵銷。**

比較只能表示在固定 16 案例內的變化，不能將有限基準推廣為任意 .NET 專案的誤報／漏報統計。

## Token 只能使用真正的執行器計數

若每個隔離案例均已使用 `token_metrics.py` 的既有格式保存 `analysis/token-usage.jsonl`，可傳入同一工作執行識別：

```bash
python "<SKILL_ROOT>/scripts/quality_acceptance.py" --workspace "<CASE_WORKSPACE>" --token-run-id "<EXECUTOR_RUN_ID>" --output "<QUALITY_RESULT>.json"
```

Token 輸出僅加總符合該 `run_id` 的實際 `input_tokens`、`output_tokens`、`cached_input_tokens`，並指出未取得紀錄的案例。缺紀錄則輸出 `null` 或未涵蓋，不推估 Token 節省比例。Token 數字不應作為降低品質標準的理由。

## CLI 結果與交付條件

- 退出碼 `0`：16 個案例及所有工件、來源、證據與回歸比較皆通過。
- 退出碼 `1`：案例缺少、證據不全、品質不符或相對前一版退步；結果保留於 JSON 供追查。
- 退出碼 `2`：工作目錄、比較紀錄或輸入格式無效。

正式接受新的安全審查版本前，建議保存模型與 Skill Git 版本、每案例原始結果、驗收 JSON 及實際可核對的執行日誌。若受時間／環境限制無法完成 16 次代理審查，應明確註記**品質實測未完成**，不可將 CI 綠燈或合成預測值宣稱為本版通過。
