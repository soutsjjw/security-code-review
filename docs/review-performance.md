# 效能診斷、來源批次與受控唯讀分工

本文件描述執行器工作流程的減負方式，**不減少 70 條規則、來源 100% 人工審閱、十類適用性、實際跨檔追查、安全控制與繞過驗證、第二輪反向複核及最終 HTML/JSON 守門**。

## 查詢與停滯處理

- `review_queue.py --compact` 只顯示未驗證的工作進度，**即使 70/70 completed 也不執行正式完整覆蓋率／規則品質驗證**，且 `ready_for_report=false`。
- `review_queue.py --detail-id AC-01` 僅取得一項完整要求；詳細對照按需取用。
- 不帶 `--compact`／`--detail-id` 的佇列，以及 `review_safety.py --validate` 和正式報告檢核，仍完整執行安全守門。
- 完整佇列的 `source_coverage.reviewed_source_file_count` 是正式驗證值；預覽的同名欄位只是候選數，不得互換。
- `logs/<run-id>.jsonl` 新增 `query_profile` 分段耗時（`load_rules`、`read_assessment`、`coverage`、`source_candidates`、`diagnostics`、`queue_total`）；`formal_coverage_observed` 記錄正式驗證已通過數，`progress_regression` 記錄進度倒退。所有計時均不是安全證據。
- 退出碼 `3` 或 `status=stalled` 必須立即停止完整審查 CLI 及自動重試；原始審查證據與 Finding 保留。查明原因後**明確**呼叫 `review_log.py --target <TARGET_ROOT> start` 才建立新的執行回合；不可自動反覆 start。

## 唯讀來源批次提示

```bash
python "<SKILL_ROOT>/scripts/review_queue.py" --target "<TARGET_ROOT>" --compact --source-batch-size 60
python "<SKILL_ROOT>/scripts/file_review_skeleton.py" --target "<TARGET_ROOT>" --batch-size 30
```

Skeleton 單次提供真實來源 SHA256、編碼、行數、多規則候選、Roslyn 方法資料與跨檔呼叫點 ID，省略逐檔開啟多種提示工具的往返。每筆 `must_read_source=true`，Agent 仍須真正讀取全文及上下游原始碼，自行撰寫 `summary`、審查方法 `methods`、十類 `category_screening`、每條 `rule_reviews`、候選排除理由。Skeleton 的 `roslyn_methods` 為程式符號，不可直接填成 `file_reviews[].methods`。

若原始碼清單或任一檔 SHA256 與結構索引快照不符，該 CLI 必須拒絕工作，先依既有來源快照復原規範處理。不可複製快取候選當作 Pass、NA 或控制已有效的證據。

## 可選擇唯讀平行分工

若執行器支援子代理，主代理可分派各子代理 **唯讀檔案閱讀、十類適用性與跨檔候選分析建議**。同一輪分工使用相同來源快照與固定 worker 數，ID 從 0 起算：

```bash
python "<SKILL_ROOT>/scripts/file_review_skeleton.py" --target "<TARGET_ROOT>" --workers 4 --worker-id 0 --batch-size 30
python "<SKILL_ROOT>/scripts/file_review_skeleton.py" --target "<TARGET_ROOT>" --workers 4 --worker-id 1 --batch-size 30
python "<SKILL_ROOT>/scripts/file_review_skeleton.py" --target "<TARGET_ROOT>" --workers 4 --worker-id 2 --batch-size 30
python "<SKILL_ROOT>/scripts/file_review_skeleton.py" --target "<TARGET_ROOT>" --workers 4 --worker-id 3 --batch-size 30
```

分片由來源相對路徑 SHA256 取模，對相同來源清單與 worker 數不重疊。若持續工作期間正式進度更新，應將初始分片工作清單固定於代理的任務內容，避免重複與漏審；每批開始前重新核實來源快照。

**唯一主代理寫入：** 子代理不得執行 `review_queue.py --init`、`review_safety.py --stage/--integrate`、`--seal-integrity`、`--snapshot-refresh`，也不得修改正式 `assessment.json`、Manifest、Journal 或結案證據。主代理逐項複核子代理意見，處理重複與衝突後，統一依現有 `--stage`、`--integrate` 契約原子保存；第二輪攻擊者視角反向複核由主代理重新閱讀來源完成。沒有子代理的執行器使用單代理流程，安全要求相同。

## Roslyn 編譯快取

`analysis_prepare.py` 以 Skill 的 `Program.cs`、indexer project、SDK 版本及執行檔路徑建立快取指紋，編譯產物放在使用者目錄 `~/.cache/security-code-review/roslyn/`，每次仍重新分析指定來源。未快取安全結論或來源 SHA256。若需停用：`SECURITY_CODE_REVIEW_ROSLYN_CACHE=0`。

## 建議驗證

使用相同 Git Revision、相同模型與執行器設定比較：Query 耗時分布、執行命令數、實測 Token、逐檔正式覆蓋率、70 條規則查核與 Finding、跨檔查證、第二輪與報告結果。未取得真實完整案例不得宣稱已達到特定加速比例。
