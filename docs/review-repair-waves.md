# 受控修復波次與分層第二輪交接

此流程僅適用**完整 70 項審查**，且正式來源快照、Manifest／Journal 與審查資料已通過既有守門。它是 **Agent 提供實際證據的受控協調器**，不是以模型自動猜測安全結論、改判 Pass 或修改受測程式。

## Wave 0～4 與實際完成界線

| 波次 | 自動化 | 必須由 Agent／審查者完成 |
| --- | --- | --- |
| Wave 0 前置檢查 | 原始來源／完整性驗證、比對完整正式追蹤工件 SHA256 與 Manifest、拒絕舊暫存或錯誤排程、建立不可覆寫的操作 checkpoint | 確認受測範圍、正式資料與來源真實性 |
| Wave 1 凍結工作 | 固定來源診斷簽章、任務與 `execution_batches` 拓樸順序 | 查核所有仍未分類的阻塞，不得擅自放寬守門 |
| Wave 2 批次證據修訂 | 驗證本批 ID／規則歸屬，轉交既有正式 `stage/integrate`，比較前後 blocker 並在新錯誤／無進展時停止 | 逐檔重讀真實來源、產生本批審查 JSON、明確取得 `--allow-revision` 授權；Finding 修訂另行授權 |
| Wave 3 風險抽樣 | 根據真實修訂（含暫停期間的外部合法修訂）自動固定高／中／低風險分層樣本；Finding、Fail、控制有效性與責任變更全部強制納入 | 人工重新閱讀來源，提供具姓名、日期、檔案、行號及摘要的抽樣紀錄；身分仍非可信驗證 |
| Wave 4 第二輪 | 重查權威第一輪診斷、抽樣是否完成，正式固定第一輪 Baseline，提供分層工作清單／讀取正式結果 | 70 條規則反向核查、高風險來源樣本、矛盾裁決與合法證據整合；沒有真實原生隔離不得宣稱獨立盲審 |

`scripts/review_repair_waves.py` 維持非正式操作 checkpoint：`<TARGET_ROOT>/reports/security-code-review/logs/repair-waves/state.json`。**它不是 Manifest／Journal 保護的正式資料**，也不能據此宣稱防竄改、審查已 Pass 或已有可信獨立覆核。遇到外部變動、舊鎖／未完成的暫存或衝突，應人工調查，不可刪除正式歷史強行重啟。

## 後續補強：P0～P2 實際執行及交付

以下為主代理可機器讀取的執行工作封包。**本腳本不能直接啟動 Codex 原生子代理**；主代理必須真的使用執行器提供的原生派工、等待與回收工具，且須按 [受控多代理契約](multi-agent-review.md) 進行可信唯讀能力試跑。環境無此能力或無法證明來源隔離時，依 `fallback=single-main-agent-actual-source-review` 降級主代理查證，**不得虛構 Agent ID／trace**。

```powershell
python "<SKILL_ROOT>/scripts/review_repair_waves.py" --target "<TARGET_ROOT>" --agent-next
```

`task_digest` 綁定本次工作規則、權威阻塞與來源／assessment SHA256；任務封包只提供待驗證範圍，不代表修復已完成。主代理仍須實際閱讀來源、形成合法 Stage payload，再逐批完成正式交易。若存在待對帳的交易意圖，任何 `--next`／`--agent-next` 都會拒絕重複套用。

正式 Stage／Integrate 前先保存非正式 `inflight` 意圖；意外中斷後必須對照 Journal、來源快照及正式證據，不能直接重放舊 payload：

```powershell
python "<SKILL_ROOT>/scripts/review_repair_waves.py" --target "<TARGET_ROOT>" --reconcile --acknowledge-investigation
```

只有確實觀察到合法的正式變更、且原始阻塞消失或相應第二輪工作仍有效，才會結案該交易意圖；正式工件沒有變動、來源快照不同或規則變更超出本批授權，必須拒收並人工調查。此流程**不呼叫 Stage／Integrate 重試**。若需額外證據，先依既有交易復原規範處理。

### Stage 成功但 Integrate 拒絕：僅取消「確定未提交」的單一批次

**先確認本機 Skill 已更新**：此功能首見於 PR #75；只合併 GitHub `develop`、重新啟動 Codex，不會自動更新 `C:\\Users\\souts\\.agents\\skills\\security-code-review`。在 Codex 實際使用的 `SKILL_ROOT`，先檢查 `scripts/review_repair_waves.py --help` 列出 `--inspect-uncommitted` 與 `--abort-uncommitted`；若沒有，**先更新本機 Skill，再重查**，不得假稱沒有安全介面。

使用唯讀預檢，**不改正式資料、不建立隔離檔案、也不用取消授權**：

```powershell
python "<SKILL_ROOT>/scripts/review_repair_waves.py" --target "<TARGET_ROOT>" --inspect-uncommitted execution-01
```

預檢結果 `needs_original_payload` 表示舊版 checkpoint 缺少語意內容指紋；尚不能取消。找到當初 `--apply-batch` 使用的原始 JSON 後，重新預檢：

```powershell
python "<SKILL_ROOT>/scripts/review_repair_waves.py" --target "<TARGET_ROOT>" --inspect-uncommitted execution-01 --payload "<ORIGINAL_PAYLOAD>.json"
```

只在 `can_abort=true`，且審查者明確授權，才可呼叫下方 `--abort-uncommitted`。**原始 payload 遺失時，不能由 staged 反推原始 JSON bytes 或假冒 SHA256 相符。** 若唯一 staged 原檔、來源快照及所有正式工件均可驗證，且另獲針對本次交易的**明確 staged-only 例外授權**，可使用原始 staged 的完整 SHA256 作為**隔離對象鎖定**（不是原始 payload 指紋）： 

```powershell
python "<SKILL_ROOT>/scripts/review_repair_waves.py" --target "<TARGET_ROOT>" --inspect-uncommitted execution-01 --expected-staged-sha256 "<STAGED_SHA256>" --allow-unbound-legacy-stage

# 只限人工逐項核對並明確授權後：
python "<SKILL_ROOT>/scripts/review_repair_waves.py" --target "<TARGET_ROOT>" --abort-uncommitted execution-01 --expected-staged-sha256 "<STAGED_SHA256>" --allow-unbound-legacy-stage --acknowledge-investigation
```

此例外只能保證**將指定 SHA256 的 staged 隔離保留，不改寫正式工件**，不能保證 staged 原本就是 inflight 的原始 payload。封存收據必須記錄 `legacy_unbound=true` 與 `raw_payload_verified=false`，供後續稽核辨識。缺乏獨立確認的 staged SHA256、正式工件不一致或未明確授權者仍維持 blocked；若已提交正式交易則走 `--reconcile`，不是取消。

若 `inflight` 仍存在，且唯一 `analysis/staged/*.json` 未入正式 Journal，先唯讀核對是否確實沒有正式交易提交。**不得直接刪除 staged、清空 inflight 或重建 Manifest／Journal**。

舊版 Wave checkpoint 僅保留原始 payload 的**檔案 SHA256**，一般取消路徑須提供當初 Stage 讀取的原始 JSON，核對 bytes 與暫存 JSON 語意（勿傳重建檔）。若確實遺失原始檔，可按下述**額外明確授權的 staged-only 例外**辦理；新版 checkpoint 另綁定 payload 語意指紋：

```powershell
python "<SKILL_ROOT>/scripts/review_repair_waves.py" --target "<TARGET_ROOT>" --abort-uncommitted execution-01 --payload "<ORIGINAL_PAYLOAD>.json" --acknowledge-investigation
```

只允許原本 `inflight` 中仍待辦的 **Wave 2 第一輪批次**，且需全部通過：

- 已由審查者查明確實沒有成功整合，且本次明確授權隔離；正式 `integrity-pending.json` 不存在，Manifest sequence/head、Journal 鏈、全部正式追蹤工件及逐條證據指紋**與交易前完全一致**。
- staged 目錄**恰有一筆** JSON、沒有其他暫存；檔名與 Stage 正規化 SHA256 對得上，`integrity_head`、來源快照、原始 payload SHA256 與內容都吻合。未知／多筆 staged、版本異動、原始檔缺失、提交狀態不明一律維持 blocked。
- 先在 `reports/security-code-review/logs/repair-waves/aborted/<EVENT_ID>/` 以不可覆寫的 `intent.json` 記錄交易與原始暫存 SHA256，之後才把原始 staged **移動並保留**為 `staged.json`，寫入 `receipt.json`；重新檢查正式資料未變更後，才清除 checkpoint 的 `inflight`。原工作批次**不標記 completed**、不重送原 payload。
- 介於封存與 checkpoint 寫入的中斷可用**同一指令**核對已存在的意圖、收據、封存 SHA 後繼續；衝突或 `state.json.pending` 殘留仍須人工鑑識，不會自動刪檔。所有隔離紀錄均為**非正式**操作日誌，不能冒稱防惡意竄改的 Journal 交易。

取消後必須**重新查核導致 Integrate 失敗的原因**，使用新、真實且合格的來源證據產生新 payload 才能重做該批；不能將上述隔離當作解除第一輪安全阻塞。

抽樣紀錄另有以 `manifest_sha256` 為起點的本機 SHA256 事件鏈；順序、內容或 head 不符須拒收。但鏈與收據仍存於非正式 checkpoint，**不是完整 Journal 綁定或防惡意竄改的可信身分證明**。身分與第二輪 L1／L2 獨立性須有執行器實際證據；否則交付獨立性標示固定為不獨立的 L0。

第二輪透過 `--agent-next` 領取新的反例／來源抽樣工作，主代理使用 `--apply-second-pass` 提交合法核查證據。所有正式驗證通過後，可**明確呼叫**：

```powershell
python "<SKILL_ROOT>/scripts/review_repair_waves.py" --target "<TARGET_ROOT>" --finalize
```

此命令先驗證完整第二輪 70 項、固定來源抽樣、非精簡 `review_queue.py` 的 `ready_for_report=true` 與 `review_safety.safety_errors`，再呼叫原有 `complete_review.py`；正式工具成功且 HTML／JSON 實際存在才建立非正式交付旁錄（SHA256、保守 L0、限制）。**不能**以旁錄取代正式 Journal、交付者身分或原有報告驗證。

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

抽樣母體為**本次真實修訂過的不同規則數** N，最小數量為 `N=0 ? 0 : min(N,max(5,ceil(0.1*N)))`；高／中／低風險分層各至少一個代表（若該層存在），Finding、Fail 異動、控制有效性與重大責任／裁決變更全部強制核對，可能超出抽樣數。抽樣憑證路徑除了需有可信 SHA256，還必須出現在該規則正式檢核證據、inspected_paths 或相關逐檔檢核紀錄中。紀錄格式：

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

這些動作**不自動填入** `adversarial_reviews` 或固定高風險來源的 `second_pass_samples`。Agent 應依 `--next` 回傳的正式 `rule_tasks`、`sample_tasks` 實際閱讀原始碼，並可使用下列入口提交**自己已查證**、且只涉及當前第二輪批次的證據：
```powershell
python "<SKILL_ROOT>/scripts/review_repair_waves.py" --target "<TARGET_ROOT>" --apply-second-pass --payload "<SECOND_PASS_PAYLOAD>.json"
python "<SKILL_ROOT>/scripts/review_repair_waves.py" --target "<TARGET_ROOT>" --next
```
若第二輪需要改寫已 completed 規則或 Finding，須另外明確授權 `--allow-revision`（Finding 另加 `--allow-finding-revision`）；誤判 fail 的撤回不經 Wave，直接依[受控撤回](review-integrity-guards.md#誤判的已確認-fail-受控撤回不刪除-finding)以 `review_safety.py` 整合。正式 `review_safety.py` 與 Journal 的安全守門不變。純反向複核／抽樣仍需逐筆核對來源、繞過假設與矛盾，不得填固定樣板。若採用子代理，若採用子代理，先依 [多代理可信能力契約](multi-agent-review.md) 完成實測與原生工具隔離。L0 表示同代理且**不獨立**；L1／L2 只有可驗證的不同代理／獨立人員實際查核才可主張，不能以 Prompt 或自填字串推定。

最後仍須執行 `review_safety.py --validate`、不帶 `--compact` 的 `review_queue.py`，確認 `ready_for_report=true`，再用 `complete_review.py` 產生並驗證 HTML／JSON 報告。協調器自己的 `ready_for_report` 僅是工作完成提示，**不是最終交付授權**。
