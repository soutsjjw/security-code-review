# P2：安全控制有效性與繞過路徑驗證

P2 不是新的安全規則，也不讓 Python 自行找漏洞或給出 `pass`。沿用現有 70 項、判定階梯、來源快照、P1 呼叫鏈結案與 HTML／JSON。只對**新 P2 索引**（`control_effectiveness_version=1`）的 `completed + pass` 靜態／混合規則要求額外人工證據。外部控制的通過條件由原先部署、制度與工件守門負責。

## Agent 的實際查核順序

1. **控制存在性**：盤點所有實際入口、完整呼叫鏈、控制執行位置與受保護操作。只看到 `[Authorize]`、Middleware 或安全 API 名稱不表示控制有效。
2. **控制有效性**：檢查執行分支、輸入／主體識別、保護條件、失敗時是否拒絕，以及部署／DI／環境覆寫是否可能改變執行路徑。
3. **反向繞過**：從未授權者、跨使用者／租戶、另一個 Endpoint、直接資料存取、Factory／DI、異常組態及編碼或重新導向等角度尋找入口。每條規則在 `review_queue.py --detail-id` 的 `control_effectiveness_guidance.required_scenarios` 中有最低檢查情境。
4. **完成判定**：發現可證實弱點 → `fail`＋Finding；靜態調查未完成 → `pending`／`blocked` 且記錄補查；只有符合共同判定階梯的真實外部阻斷才可 `review`。確認無可繞過的適用路徑且符合 `pass_condition`，才整理 P2 紀錄並標 `pass`。

`not_applicable` 僅用於某個特定繞過情境**經來源核對後確實不適用**，須附理由與真實證據；不可把沒有測試或沒有關鍵字視為不適用。所有情境的 `unresolved` 必須留在補查階段，不得完成 pass。

## 工作中證據（不變更正式 assessment Schema）

在 P0/P1 已使用的 `review_safety.py --stage` 工作批次中加入 `control_verifications`。以下只示意資料**形狀**，路徑、行號、SHA256、Git 版本和判定理由都必須取自受測專案真實審查，不得直接複製：

```json
{
  "control_verifications": {
    "AC-08": {
      "status": "pass",
      "git_revision": "<review-snapshot.json 目前 git_revision>",
      "snapshot_fingerprint": "<整份來源快照的 fingerprint>",
      "source_hashes": {
        "src/OrderController.cs": "<此檔快照 SHA256>",
        "src/OrderService.cs": "<此檔快照 SHA256>",
        "src/OrderRepository.cs": "<此檔快照 SHA256>"
      },
      "entry_points": [
        {"path": "src/OrderController.cs", "line_start": 10, "line_end": 10}
      ],
      "enforcement_points": [
        {"path": "src/OrderService.cs", "line_start": 24, "line_end": 24}
      ],
      "protected_operations": [
        {"path": "src/OrderRepository.cs", "line_start": 31, "line_end": 31}
      ],
      "control_condition": "描述真實可證明的主體識別及物件層級授權條件",
      "failure_behavior": "描述授權拒絕時真正執行的拒絕／不回傳分支",
      "search_summary": "描述已檢查的所有資料存取入口、查詢路徑及 DI 實作",
      "bypass_scenarios": [
        {
          "scenario": "horizontal_access",
          "outcome": "blocked",
          "reason": "描述如何以來源證據核對跨使用者物件讀取必遭拒絕",
          "evidence": [
            {"path": "src/OrderService.cs", "line_start": 24, "line_end": 24}
          ]
        }
      ],
      "open_issues": []
    }
  }
}
```

範例中的 `bypass_scenarios` **不完整，不能用於 AC-08 結案**；所有 `required_scenarios` 均需個別記錄，`outcome` 為 `blocked` 或經證據查明的 `not_applicable`，且每條有具體理由和可定位來源證據。`enforcement_points` 至少一筆必須與正式 `checks[].evidence` 位置重疊。所有紀錄路徑都必須列入該規則的 `execution.inspected_paths`，並與現有來源快照一致。`snapshot_fingerprint` 由整份來源清單、SHA256 與 Git Revision 計算，避免不在當前證據路徑內的其他檔案新增後，舊的 `pass` 仍被沿用。

```bash
python "<SKILL_ROOT>/scripts/review_queue.py" --target "<TARGET_ROOT>" --detail-id AC-08
python "<SKILL_ROOT>/scripts/control_effectiveness.py" --target "<TARGET_ROOT>" --snapshot-fingerprint
python "<SKILL_ROOT>/scripts/review_safety.py" --target "<TARGET_ROOT>" --stage "<TARGET_ROOT>/reports/security-code-review/analysis/p2-batch.json"
python "<SKILL_ROOT>/scripts/review_safety.py" --target "<TARGET_ROOT>" --integrate
python "<SKILL_ROOT>/scripts/review_safety.py" --target "<TARGET_ROOT>" --validate
```

`control_verifications` 會儲存為 `reports/security-code-review/analysis/control-verifications.json`，不進入正式 `assessment.json`，也不會被算入來源覆蓋。重複提交相同內容是可重試的；內容不同須人工核對後明確使用 `--allow-revision`，不能覆寫 Finding。

## 版本遷移與邊界

- 初次使用 P2 時，`analysis_prepare.py --mode full` 會寫入 P2 索引版本；**既有已完成 pass 不自動繼承有效性**，需對照新工作證據重新查核，補上真實結案紀錄。保留 assessment、Finding、舊 `file_reviews`。
- 快照或 Git Revision 改變時，原有 P2 紀錄會因路徑與版本核對失敗而拒絕結案，Agent 必須重新閱讀已受影響來源。不可只更新 hash／理由文字。
- P1 `callsite_reviews` 與 P2 `control_verifications` 分別驗證呼叫點追查和控制實際生效，**兩者都需要**。沒有 Roslyn／CodeGraph 時仍由 Agent 人工建立真實控制鏈。
- 規則本身若在儲存庫找不到應有的控制，應依既有判定階梯 `fail`＋Finding，而非因缺少 P2 紀錄改為 `review`。
- P2 機械驗證能確保資料來源可定位、版本一致、必要情境已記錄，但**不能獨立證明攻擊者無法繞過**；仍必須由主代理閱讀並分析原始碼。
- 未來擴充 .NET Framework／Vue 時，可共用此工作證據契約；分析器本身仍需依語言擴充。
