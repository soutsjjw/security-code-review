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

## Codex 原生子代理啟動（完整模式）

本 Skill 的 Python 腳本不具備啟動模型代理的權限；`file_review_skeleton.py --workers N` **只負責唯讀工作分片**。真正的主代理 + N 名子代理必須由 Codex 執行器的原生委派／spawn 能力完成，不能透過重複呼叫腳本冒充多代理。

1. 主代理先完成 Python 固定、結構索引、`review_queue.py --init`、來源快照與 `review_safety.py --plan`；固定本輪應審查來源清單、`TARGET_ROOT` 與 SHA256。來源或證據快照無法驗證時應先排除問題，**不得**以降為單代理取代修復。
2. 主代理檢查**目前工作階段是否真的提供可用的原生子代理工具**，而非檢查 `.git`。可用且至少有兩名並行名額、有足夠獨立來源工作時，主動產生 N=2～4（不得超過執行器限制）個子代理，逐一交付不同 `worker-id`；使用者不必額外重複要求啟動。各子代理共用同一受測目錄、固定 worker 數和快照，不要求獨立 Git worktree。
3. 每名子代理僅讀取來源與唯讀分析提示。子代理必須實際呼叫所屬 `--workers N --worker-id K --offset 0`，依 `next_offset` 分頁到 `null`，逐檔閱讀源碼全文與需要的跨檔關聯、全部十類適用性，回傳檔案路徑、真實行號、SHA256、候選規則、控制鏈、疑點和不確定之處。不得臆造判定或將候選當成證據。
4. 主代理等待所有子代理回報並記錄實際**啟動數、完成數、失敗原因及分片覆蓋**；驗證每個 worker ID、來源版本、路徑及分片不重複，親自重查規則、攻擊面與跨分片呼叫鏈，處理矛盾後才開始正式批次整合。子代理失敗、逾限或退出時，未完成分片由主代理重新安排唯讀分析或接手；不得宣稱原分片完成。
5. 只有**原生子代理功能不存在、被禁止、啟動失敗或名額不足 2** 才降級為單代理；記錄可觀察到的工具／能力診斷，不可將「不是 Git repo」寫成降級理由，也不因缺少 Git 而停止來源審查。若不能確認能力，記錄「無法確認」而非斷言不存在。

例如 N=4 時的每名子代理所需唯讀分片命令（**下列四行不會自行啟動代理**）：

```bash
python "<SKILL_ROOT>/scripts/file_review_skeleton.py" --target "<TARGET_ROOT>" --workers 4 --worker-id 0 --batch-size 30
python "<SKILL_ROOT>/scripts/file_review_skeleton.py" --target "<TARGET_ROOT>" --workers 4 --worker-id 1 --batch-size 30
python "<SKILL_ROOT>/scripts/file_review_skeleton.py" --target "<TARGET_ROOT>" --workers 4 --worker-id 2 --batch-size 30
python "<SKILL_ROOT>/scripts/file_review_skeleton.py" --target "<TARGET_ROOT>" --workers 4 --worker-id 3 --batch-size 30
```

工作分片由來源相對路徑 SHA256 取模，對相同來源清單與固定 N 不重疊。各 worker 由 `--offset 0` 起，依 `next_offset` 分頁；主代理必須在本輪所有分片回報與核對完畢後，才更新正式審查資料，以免待辦清單改變造成漏檔。沒有 `.git` 的檔案目錄也可依檔案 SHA256 驗證快照；Git Revision 不可用時須明示，禁止捏造或跨來源快照沿用證據。需要 Git worktree 的寫入隔離功能與此唯讀代理模式無關。

**唯一主代理寫入：** 子代理不得執行 `review_queue.py --init`、`review_safety.py --stage/--integrate`、`--seal-integrity`、`--snapshot-refresh`，也不得修改正式 `assessment.json`、Manifest、Journal、分析索引或來源檔。主代理逐項複核子代理意見、統一依現有 `--stage/--integrate` 契約原子保存；第二輪攻擊者視角反向複核仍由主代理重讀來源完成。不論單／多代理，70 項、來源覆蓋及安全守門均不得縮減。

## Roslyn 編譯快取

`analysis_prepare.py` 以 Skill 的 `Program.cs`、indexer project、SDK 版本及執行檔路徑建立快取指紋，編譯產物放在使用者目錄 `~/.cache/security-code-review/roslyn/`，每次仍重新分析指定來源。未快取安全結論或來源 SHA256。若需停用：`SECURITY_CODE_REVIEW_ROSLYN_CACHE=0`。

## 建議驗證

使用相同 Git Revision、相同模型與執行器設定比較：Query 耗時分布、執行命令數、實測 Token、逐檔正式覆蓋率、70 條規則查核與 Finding、跨檔查證、第二輪與報告結果。未取得真實完整案例不得宣稱已達到特定加速比例。
