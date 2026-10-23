# 待確認判定與外部證據裁決

本驗證機制延續既有「共同證據與結果判定」階梯，**不改變** 70 條規則、`pass/fail/review/na` 定義、正式 `assessment.json` Schema 或 HTML／JSON 報告。目標是避免尚未完成的靜態分析、非必要測試缺口，以及已經證明的程式碼弱點被寫成 `completed + review`。判定裁決驗證不能取代主代理實際閱讀原始碼，也**不會自動把 review 改成 pass**。

## 判定順序

1. 靜態程式碼、設定或呼叫鏈確認弱點／應有控制缺席：**`fail`＋Finding**。不得要求先提供攻擊實測或部署工件才紀錄漏洞。
2. 靜態控制符合 `pass_condition`，沒有真正影響結論的外部限制：**`pass`**，並通過 控制有效性檢核。缺測試本身不構成 `review`。
3. 已完成程式碼追查，但尚缺**確實影響判定**且已明確命名的外部資料：**`review`**，附上判定裁決證據。靜態／混合規則使用 `review_kind=static_done_external_pending`；純外部控制才可 `external_only`。
4. 程式碼分析仍未完成：`execution.state=pending/blocked`，不可用 `completed+review` 掩飾。
5. 已核對確實不適用與責任範圍：`na`。

規則 `manual_boundary` 只是可供查證的外部邊界，**不是每條規則自動列為 review 的理由**。例如 AC-01 的 Session 有效期限已實作且會過期，通常可由靜態來源判斷；僅當組織**實際存在的逾時長度正式政策**是否符合會改變該規則結論，才使用 `review`。IN-07 同理，只有真正無法由儲存庫取得且具決定性的主機符號連結／Volume／ACL 資料才可待確認。

## 批次判定證據格式

已啟用判定裁決的新索引（`decision_adjudication_version=1`）要求所有 `completed+review` 附一份工作中 `decision_audits`。以下為**結構示意，非已完成證據**：

```json
{
  "decision_audits": {
    "AC-01": {
      "status": "review",
      "review_kind": "static_done_external_pending",
      "git_revision": "<review-snapshot.json git_revision>",
      "snapshot_fingerprint": "<整份來源快照的雜湊>",
      "static_result": "control_satisfied",
      "static_conclusion": "已追查實際入口、逾期拒絕分支及設定覆寫，程式碼所能確認的控制已符合",
      "searched_paths": ["src/Infrastructure/Identity/SessionValidator.cs"],
      "static_evidence": [
        {"path": "src/Infrastructure/Identity/SessionValidator.cs",
         "line_start": 42, "line_end": 44}
      ],
      "external_gap": {
        "category": "organization_policy",
        "artifact": "正式 Session 絕對逾時政策核定文件",
        "blocking_question": "核定的 Session 逾時上限是否低於程式碼目前使用的期限",
        "why_decisive": "原始碼能證實逾期會被拒絕，但無法得知組織正式核定的時效標準",
        "manual_boundary": "逾時長度是否符合組織政策"
      },
      "open_static_questions": []
    }
  }
}
```

- `static_result=control_satisfied`：已由來源／設定核對**靜態控制部分**，不是對整項規則或正式環境自動給 pass；必須同時有 `searched_paths`、`static_evidence` 與正式 `checks[].evidence` 的行號關聯。
- `review_kind=external_only`：僅允許判定矩陣 `mode=external`，搭配 `static_result=external_control`。需具體證明缺的是本質上無法僅用程式碼觀察的部署、營運或制度證據；現有完成證據、逐檔記錄仍不可省略。
- `external_gap.category`：`deployment`、`operational_record`、`organization_policy`、`platform_configuration`、`external_scan`。**沒有**「缺少動態測試」類別。掃描結果只有在實際嘗試取得／執行但失敗時可使用 `external_scan`，須包含 `attempted_command` 和 `failure_detail`。
- `external_gap.artifact`：明確命名工件，且正式 `decision_reason` 須包含「待確認：」及該工件；`blocking_question` 和 `why_decisive` 必須說明工件會如何影響安全判定。
- `external_gap.manual_boundary`：須取自本規則 `policies/review-decision-matrix.json` 中的 `manual_boundary`，而且**必須真的對應當前情況**。字串相同只能由機械驗證核對，相關性仍由 Agent 判斷。
- `open_static_questions=[]` 表示**真的**已追查完畢；仍有待追的 Handler、Controller、資料流或 DI 不可填空以通過守門。

以 `review_safety.py --stage <JSON>`、`--integrate` 保存至 `reports/security-code-review/analysis/decision-audits.json`。相同紀錄可重試，修改既有紀錄須先人工核對並使用明確的 `--allow-revision`；不得覆寫或刪除 Finding。

## 查詢與驗收

```bash
python "<SKILL_ROOT>/scripts/review_queue.py" --target "<TARGET_ROOT>" --detail-id AC-01
python "<SKILL_ROOT>/scripts/control_effectiveness.py" --target "<TARGET_ROOT>" --snapshot-fingerprint
python "<SKILL_ROOT>/scripts/review_safety.py" --target "<TARGET_ROOT>" --stage "<實際批次.json>"
python "<SKILL_ROOT>/scripts/review_safety.py" --target "<TARGET_ROOT>" --integrate
python "<SKILL_ROOT>/scripts/review_safety.py" --target "<TARGET_ROOT>" --validate
```

每項 `--detail-id` 會提供 `decision_adjudication_guidance`，包括 `mode`、`manual_boundary`、允許的外部缺口與工作證據欄位。完成 70 項後，`review_queue.py` 的 `recheck_rule_ids` 會列出仍有缺口的項目；**不自行修改既有狀態或結論**。

測試：

```bash
python -m unittest discover -s tests -p "test_p3_adjudication.py" -v
python -m unittest discover -s tests -v
python scripts/validate_package.py
```

測試已知弱點、實際外部待確認、來源證據不成立、錯誤邊界、制式缺測試、未完成分析與衝突整合；**基準單元測試不代表已執行 16 個案例的完整 Agent 審查**。

## 版本相容性

未具判定裁決契約的既有索引不會被新版工具默默改寫；建立新版索引後，既有 `review` 須依判定裁決契約補充真實的外部缺口與靜態證據。原本的 `pass/fail`、Finding 和正式報告資料均不會自動刪除或改判。未來新增 .NET Framework／Vue 分析器時可沿用工作中證據契約，但必須建立對應語言的來源語意查核能力。
