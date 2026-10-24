# 安全控制有效性與繞過路徑驗證

此驗證機制不新增安全規則，也不讓 Python 自行找漏洞或自動變更 Pass／Fail／Review。沿用現有 70 項、判定階梯、來源快照、跨檔結案與 HTML／JSON。`control_effectiveness_version=1` 保留既有靜態／混合 `completed + pass` 守門；新索引另啟用 `control_outcome_version=1`，檢查具程式碼控制證據的 `completed + fail`，以及已完成靜態查核的 `completed + review`。純外部部署／政策結論仍由專用外部證據驗證處理，不捏造程式碼入口。

## Agent 的實際查核順序

1. **控制存在性**：盤點所有實際入口、完整呼叫鏈、控制執行位置與受保護操作。只看到 `[Authorize]`、Middleware 或安全 API 名稱不表示控制有效。
2. **控制有效性**：檢查執行分支、輸入／主體識別、保護條件、失敗時是否拒絕，以及部署／DI／環境覆寫是否可能改變執行路徑。
3. **反向繞過**：從未授權者、跨使用者／租戶、另一個 Endpoint、直接資料存取、Factory／DI、異常組態及編碼或重新導向等角度尋找入口。每條規則在 `review_queue.py --detail-id` 的 `control_effectiveness_guidance.required_scenarios` 中有最低檢查情境。
4. **完成判定**：發現可證實弱點 → `fail`＋Finding；靜態調查未完成 → `pending`／`blocked` 且記錄補查；只有符合共同判定階梯的真實外部阻斷才可 `review`。確認無可繞過的適用路徑且符合 `pass_condition`，才整理控制有效性紀錄並標 `pass`。

`not_applicable` 僅用於某個特定繞過情境**經來源核對後確實不適用**，須附理由與真實證據；不可把沒有測試或沒有關鍵字視為不適用。所有情境的 `unresolved` 必須留在補查階段，不得完成 pass。

## 工作中證據（不變更正式 assessment Schema）

在原有來源完整性與跨檔結案流程所使用的 `review_safety.py --stage` 工作批次中加入 `control_verifications`。以下只示意資料**形狀**，路徑、行號、SHA256、Git 版本和判定理由都必須取自受測專案真實審查，不得直接複製：

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
python "<SKILL_ROOT>/scripts/review_safety.py" --target "<TARGET_ROOT>" --stage "<TARGET_ROOT>/reports/security-code-review/analysis/control-review-batch.json"
python "<SKILL_ROOT>/scripts/review_safety.py" --target "<TARGET_ROOT>" --integrate
python "<SKILL_ROOT>/scripts/review_safety.py" --target "<TARGET_ROOT>" --validate
```

`control_verifications` 會儲存為 `reports/security-code-review/analysis/control-verifications.json`，不進入正式 `assessment.json`，也不會被算入來源覆蓋。重複提交相同內容是可重試的；內容不同須人工核對後明確使用 `--allow-revision`，不能覆寫 Finding。

## 已完成 Fail／Review 的控制結果證據（全 70 項適用規則）

在新版索引中，仍使用同一份 `control_verifications` 與既有 `review_safety.py --stage`／`--integrate` 工作流程。 `assessment.json` 不新增欄位。 **Fail／Review 的格式與 Pass 不同**，不能將 Pass 的 blocked 情境直接複製成 Fail。

| 判定 | 必備來源證據 | 必備反向情境及關聯 |
|---|---|---|
| `pass` | 既有的入口、執行點、保護操作、拒絕分支 | 所有最低繞過情境必須已阻擋／真正不適用 |
| `fail`（程式碼控制） | `entry_points`、`failure_points`、`protected_operations`；`failure_mode`、`failure_reason`、`search_summary` | 至少一個 `confirmed_vulnerability`，且失效來源須同時與正式規則證據及已保存 Finding 證據重疊 |
| `review`（靜態部分已完成） | `entry_points`、`enforcement_points`、`protected_operations`；`control_condition`、`failure_behavior`、`search_summary` | 涵蓋規則最低反向情境，結果限 `blocked`／`not_applicable`／`external_boundary`，至少一個為決定性外部邊界；`external_gap_artifact` 須對應 `decision-audits.json` |

Fail 的 `failure_mode` 可為 `control_absent`、`ineffective_enforcement`、`bypass_path`、`unsafe_configuration`；缺陷確認後不可因還沒測完所有其他情境而退回 Review，但若程式碼分析本身尚有未解問題，仍不得宣稱整體完成。

所有情境須附真實來源 `evidence` 陣列、具體原因，與本次 `execution.inspected_paths` 和來源快照 SHA256 一致。`open_issues=[]` 必須代表目前必要的程式碼追查已完成，不得為了過守門填空。純外部 `external_only` Review 或僅有外部工件的部署 Fail 不要求上述程式碼證據，但原有外部判定及 Finding 守門仍須通過。

以下示意 **只是資料欄位格式，不可抄用為真實證據**：

```json
{
  "control_verifications": {
    "AC-01": {
      "status": "fail",
      "git_revision": "<目前快照 Git revision>",
      "snapshot_fingerprint": "<目前完整來源快照指紋>",
      "source_hashes": {"src/SessionValidator.cs": "<Validator 真實 SHA256>",
                        "src/SessionEndpoint.cs": "<Endpoint 真實 SHA256>"},
      "entry_points": [{"path": "src/SessionEndpoint.cs", "line_start": 20, "line_end": 20}],
      "failure_points": [{"path": "src/SessionValidator.cs", "line_start": 42, "line_end": 42}],
      "protected_operations": [{"path": "src/SessionEndpoint.cs", "line_start": 24, "line_end": 24}],
      "failure_mode": "ineffective_enforcement",
      "failure_reason": "描述為何真實驗證器會接受已過期的工作階段",
      "search_summary": "描述完整調查的其他入口與驗證分支",
      "bypass_scenarios": [{
        "scenario": "expired_session",
        "outcome": "confirmed_vulnerability",
        "reason": "描述已確認的失效流程",
        "evidence": [{"path": "src/SessionValidator.cs", "line_start": 42, "line_end": 42}]
      }],
      "open_issues": []
    }
  }
}
```

`control_verifications` 不會自行產生 Finding；必須先在正式 `assessment.json` 保存 Finding、證據與 `checks[].finding_ids`，才能為其完成關聯驗證。若判定或快照改變，舊的結果證據不得自動繼承。用 `review_queue.py --detail-id AC-01` 可取得規則的控制情境要求。

這是結構完整性驗證，不是可執行漏洞利用證明；不自動補全來源呼叫鏈，也不以大量新增文字代替程式碼追查。

## 版本遷移與邊界

- 首次導入控制有效性驗證時，`analysis_prepare.py --mode full` 會寫入 `control_effectiveness_version`；**既有已完成 pass 不自動繼承有效性**，需對照新工作證據重新查核，補上真實結案紀錄。保留 assessment、Finding、舊 `file_reviews`。
- 快照或 Git Revision 改變時，既有控制有效性紀錄會因路徑與版本核對失敗而拒絕結案，Agent 必須重新閱讀已受影響來源。不可只更新 hash／理由文字。
- `callsite_reviews` 與 `control_verifications` 分別驗證呼叫點追查和控制實際生效，**兩者都需要**。沒有 Roslyn／CodeGraph 時仍由 Agent 人工建立真實控制鏈。
- 規則本身若在儲存庫找不到應有的控制，應依既有判定階梯 `fail`＋Finding，而非因缺少控制有效性紀錄改為 `review`。
- 機械驗證能確保資料來源可定位、版本一致、必要情境已記錄，但**不能獨立證明攻擊者無法繞過**；仍必須由主代理閱讀並分析原始碼。
- 未來擴充 .NET Framework／Vue 時，可共用此工作證據契約；分析器本身仍需依語言擴充。
