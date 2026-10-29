# 受控修復波次與分層第二輪交接

此流程僅適用**完整 70 項審查**，且正式來源快照、Manifest／Journal 與審查資料已通過既有守門。它是 **Agent 提供實際證據的受控協調器**，不是以模型自動猜測安全結論、改判 Pass 或修改受測程式。

## Wave 0～4 與實際完成界線

| 波次 | 自動化 | 必須由 Agent／審查者完成 |
| --- | --- | --- |
| Wave 0 前置檢查 | 原始來源／完整性驗證、拒絕舊暫存或錯誤排程、建立不可覆寫的操作 checkpoint | 確認受測範圍、正式資料與來源真實性 |
| Wave 1 凍結工作 | 固定來源診斷簽章、任務與 `execution_batches` 拓樸順序 | 查核所有仍未分類的阻塞，不得擅自放寬守門 |
| Wave 2 批次證據修訂 | 驗證本批 ID／規則歸屬，轉交既有正式 `stage/integrate`，比較前後 blocker 並在新錯誤／無進展時停止 | 逐檔重讀真實來源、產生本批審查 JSON、明確取得 `--allow-revision` 授權；Finding 修訂另行授權 |
| Wave 3 風險抽樣 | 根據本次實際修訂規則自動固定抽樣集合；Finding、Fail 變更及控制責任修改全部強制納入 | 人工重新閱讀來源，提供具姓名、日期、檔案、行號及摘要的抽樣紀錄；身分仍非可信驗證 |
| Wave 4 第二輪 | 重查權威第一輪診斷、抽樣是否完成，正式固定第一輪 Baseline，提供分層工作清單／讀取正式結果 | 70 條規則反向核查、高風險來源樣本、矛盾裁決與合法證據整合；沒有真實原生隔離不得宣稱獨立盲審 |

`scripts/review_repair_waves.py` 維持非正式操作 checkpoint：`<TARGET_ROOT>/reports/security-code-review/logs/repair-waves/state.json`。**它不是 Manifest／Journal 保護的正式資料**，也不能據此宣稱防竄改、審查已 Pass 或已有可信獨立覆核。遇到外部變動、舊鎖／未完成的暫存或衝突，應人工調查，不可刪除正式歷史強行重啟。

## 操作順序

先執行 `analysis_prepare.py`、`review_queue.py --diagnose-first-pass` 取得真實審查狀態。當有可修復的既有 blocker，使用：

```powershell
python "<SKILL_ROOT>/scripts/review_repair_waves.py" --target "<TARGET_ROOT>" --start
python "<SKILL_ROOT>/scripts/review_repair_waves.py" --target "<TARGET_ROOT>" --next
```

`--start` 只可執行一次。若有未知或無法排程的 blocker，回傳 blocked 並保留所有正式資料。每一輪依 `next_batch.task_ids` 回到真實來源檔、設定、呼叫鏈與 Finding，產生經審查者核對的 `<BATCH_PAYLOAD>.json`，例如現有 `review_safety.py --stage` 所支援的 `checks`、`file_reviews`、`closures`、`control_verifications`、`decision_audits`、`findings` 結構，不新增未核對的制式紀錄。整合命令：

```powershell
python "<SKILL_ROOT>/scripts/review_repair_waves.py" --target "<TARGET_ROOT>" --apply-batch execution-01 --payload "<BATCH_PAYLOAD>.json" --allow-revision
python "<SKILL_ROOT>/scripts/review_repair_waves.py" --target "<TARGET_ROOT>" --next
```

`--allow-revision` **僅限使用者對本次特定審查明確授權**；不能由文件示例視為已授權。Finding 既有內容修訂須另以 `--allow-finding-revision` 授權，既有正式交易仍會檢查理由、審查人員、嚴重度與原始證據。

無進展、來源快照異動、新增權威阻塞類型、4 筆以上新 blocker、完整性損壞或其他既有交易拒絕時，保持 `blocked`／退出碼 2、或 `paused`／退出碼 3，禁止自動 rollback、重建 Manifest、刪 Finding 或循環重試。**整合成功但 checkpoint 寫入失敗**是需要人工核對的事故，不能自動再套用同一 payload。

暫停後不能直接忽略舊結果。只有人工查明問題、合法完成額外的正式證據交易，且來源快照維持一致、權威阻塞指紋確實改變、未產生新增的拒絕條件時，才可明確續跑：

```powershell
python "<SKILL_ROOT>/scripts/review_repair_waves.py" --target "<TARGET_ROOT>" --resume --acknowledge-investigation
```

續跑會重新診斷、核對原始錯誤是否真正消失，再恢復仍待處理的批次；口頭確認不能取代正式 evidence、Journal 或來源驗證。

第一輪所有批次完成、`ready_for_second_pass=true` 後進行風險抽樣：

```powershell
python "<SKILL_ROOT>/scripts/review_repair_waves.py" --target "<TARGET_ROOT>" --sample-plan
python "<SKILL_ROOT>/scripts/review_repair_waves.py" --target "<TARGET_ROOT>" --record-sample "<SAMPLE_RECEIPT>.json"
```

抽樣母體為**本次真實修訂過的不同規則數** N，最小數量為 `N=0 ? 0 : min(N,max(5,ceil(0.1*N)))`；加上 Finding、Fail 異動、重大結案／責任變更全部強制核對，可能超出抽樣數。紀錄格式：

```json
{
  "rule_id": "AC-01",
  "reviewer": "經授權的人工覆核者",
  "reviewed_on": "2026-10-29",
  "outcome": "verified",
  "review_summary": "以實際重讀的來源控制分支、授權檢查與可能繞過路徑記錄至少四十字的具體覆核說明。",
  "evidence": {"path": "src/Web/Program.cs", "line_start": 1, "line_end": 25}
}
```

日期、來源、行號與目前可信 SHA256 必須吻合；上方內容純示例，**不得直接當正式查核證據提交**。`--record-sample` 只記錄審查者提供的聲明，不驗證真人身分，不可把這項人工抽樣計成已有 L1／L2 獨立複核。

通過抽樣後才正式啟動第二輪：

```powershell
python "<SKILL_ROOT>/scripts/review_repair_waves.py" --target "<TARGET_ROOT>" --begin-second-pass
python "<SKILL_ROOT>/scripts/review_repair_waves.py" --target "<TARGET_ROOT>" --next
python "<SKILL_ROOT>/scripts/review_repair_waves.py" --target "<TARGET_ROOT>" --verify-second-pass
```

這些動作**不自動填入** `adversarial_reviews` 或固定高風險來源的 `second_pass_samples`。Agent 必須依 `second_pass_layers.py` 真實閱讀來源、以 `review_safety.py --stage/--integrate` 提交；若採用子代理，先依 [多代理可信能力契約](multi-agent-review.md) 完成實測與原生工具隔離。L0 表示同代理且**不獨立**；L1／L2 只有可驗證的不同代理／獨立人員實際查核才可主張，不能以 Prompt 或自填字串推定。

最後仍須執行 `review_safety.py --validate`、不帶 `--compact` 的 `review_queue.py`，確認 `ready_for_report=true`，再用 `complete_review.py` 產生並驗證 HTML／JSON 報告。協調器自己的 `ready_for_report` 僅是工作完成提示，**不是最終交付授權**。
