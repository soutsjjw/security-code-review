# 增量驗證、收斂診斷與灰度／端到端驗收

本頁描述 opt-in 流程的**輔助工具**。不修改受測產品原始碼；不允許以增量結果代替第一輪的正式全量守門。既有 70 項規則、100% 來源覆蓋、Finding、Manifest／Journal 以及獨立第二輪均保持不變。

## 增量驗證（修復循環內）

在來源快照與工具版本完全一致、已有完整的逐檔／規則責任記錄時，可用 `incremental_verification.py` 提出工作範圍；其結果**永遠不宣稱 `full_gate_passed=true` 或 `ready_for_second_pass=true`**。

```bash
python <SKILL_ROOT>/scripts/incremental_verification.py --target <TARGET_ROOT> --changes <VERIFIED_CHANGES_JSON> --previous-contract <PREVIOUS_CONTRACT_SHA256>
python <SKILL_ROOT>/scripts/incremental_verification.py --target <TARGET_ROOT> --changes <VERIFIED_CHANGES_JSON> --previous-contract <PREVIOUS_CONTRACT_SHA256> --compare-full
```

變更描述 JSON 可含 `changed_paths`、`changed_rule_ids`、`changed_artifacts`。僅有工具／代理自行宣稱的變更範圍不是可信證據。當變更觸及共用工件、版本指紋、索引、依賴圖或來源範圍不明確時，工具回傳 `full_recheck=true`，不得縮小查核。此版本未具備正式交易的逐欄差異收據，因此 `changed_artifacts` 一律要求全量重驗。

`sample_rules` 使用高風險規則優先、固定 seed 的抽樣協助比較；它不是第二輪複核，也不會替代全部規則驗證。每次正式進入第二輪之前，仍必須執行既有 `review_safety.py --begin-second-pass` 的第一輪完整性驗證；正式報告之前仍需完整 `--validate` 與 `quality_gate.py`。

## 收斂診斷與策略切換

```bash
python <SKILL_ROOT>/scripts/convergence_controller.py --target <TARGET_ROOT>
```

工具使用正式 Blocker 診斷，將根因分組並提供有限、可機器比對的策略簽章。K=3、M=3 只是**暫定診斷觸發值**；B0 未校準前不得作為驗收門檻，不得因此停止整個審查。

只有完成來源查核後，才能以 `--category`、`--group-key`、`--strategy-id`、`--evidence-receipt` 登記合法策略嘗試。策略耗盡時產生 `exhausted_requires_evidence`，不得自動寫入假證據或讓整個 Run 變成 `blocked`；其餘獨立工作繼續進行。

當 `SECURITY_CODE_REVIEW_EXECUTION_MODE=optimized` 時，原本 15 分鐘＋4 次 checkpoint 的舊停滯門檻只會要求收斂診斷，不直接強制進入 `stalled`。legacy 模式的既有行為不變。執行時若真正缺乏合法續行途徑，仍應保留權威 Blocker、策略紀錄與人工介入條件。

## G1 真實小型專案灰度關卡

```bash
python <SKILL_ROOT>/scripts/flow_acceptance.py --mode g1 --target <OPTIMIZED_TARGET> --before-assessment <PREVIOUS_ASSESSMENT_JSON> --shadow-legacy <LEGACY_DIAG_JSON> --shadow-optimized <OPTIMIZED_DIAG_JSON> --legacy-target <LEGACY_RESUME_TARGET> --output <G1_JSON>
```

G1 驗證正式 Finding 未消失或未經授權改寫、已有有效第一輪全量檢查、已建立第二輪 baseline、原有 Journal／Manifest 可核對、不同模式的安全診斷沒有未裁決差異、舊格式狀態可繼續核對，以及沒有尚未裁決的 `block` 事件。L3 僅能取得 `conditional-audit-only`，不能宣稱強制隔離。

**注意**：任何無可信人工覆核通道的 `block` 事件都必須保留待覆核，不能以程式自動「推翻」。G1 失敗需回到對應的交易、證據或診斷模組修正，之後重新驗收，不能以執行過一次當成通過。

## E2E 完整正式驗收

```bash
python <SKILL_ROOT>/scripts/flow_acceptance.py --mode e2e --target <TARGET_ROOT> --output <E2E_JSON>
```

E2E 直接使用既有 `quality_gate.measure`，要求真實 70 條規則、100% 原始碼覆蓋、合法第二輪 70 條、嚴格 HTML／JSON 報告及 Findings／證據一致性。單元測試的 mock 只能驗證守門流程，**不代表 581 檔案專案的端到端驗收已完成**。

完整效能改善須先在同一固定版本專案執行 B0 與新版至少多次獨立比較。Token、Agent 耗時不具可信執行器量測來源時必須標記 unavailable，不能宣稱效能下降已被解決。
