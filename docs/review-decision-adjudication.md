# 待確認判定與外部證據裁決

本驗證機制延續既有「共同證據與結果判定」階梯，**不改變** 70 條規則、`pass/fail/review/na` 定義、正式 `assessment.json` Schema 或 HTML／JSON 報告。目標是避免尚未完成的靜態分析、非必要測試缺口，以及已經證明的程式碼弱點被寫成 `completed + review`。判定裁決驗證不能取代主代理實際閱讀原始碼，也**不會自動把 review 改成 pass**。

## 判定順序

1. 靜態程式碼、設定或呼叫鏈確認弱點／應有控制缺席：**`fail`＋Finding**。不得要求先提供攻擊實測或部署工件才紀錄漏洞。
2. 靜態控制符合 `pass_condition`，沒有真正影響結論的外部限制：**`pass`**，並通過 控制有效性檢核。缺測試本身不構成 `review`。
3. 已完成程式碼追查，但尚缺**確實影響判定**且已明確命名的外部資料：**`review`**，附上判定裁決證據。靜態／混合規則使用 `review_kind=static_done_external_pending`；純外部控制才可 `external_only`。
4. 程式碼分析仍未完成：`execution.state=pending/blocked`，不可用 `completed+review` 掩飾。
5. 已核對確實不適用與責任範圍：`na`。

規則 `manual_boundary` 只是可供查證的外部邊界，**不是每條規則自動列為 review 的理由**。例如 AC-01 的 Session 有效期限已實作且會過期，通常可由靜態來源判斷；僅當組織**實際存在的逾時長度正式政策**是否符合會改變該規則結論，才使用 `review`。IN-07 同理，只有真正無法由儲存庫取得且具決定性的主機符號連結／Volume／ACL 資料才可待確認。

## 可查證的外部控制責任（適用全 70 項）

驗證器一律先看證據，不把缺少 Workflow、Lockfile、CI Runner、套件掃描或部署程式碼視為安全，也不要求虛構來源行號。

- `static_done_external_pending`：程式碼控制已證實符合靜態部分，`static_result=control_satisfied`，須有真正的 `static_evidence`。
- `external_only`：僅限矩陣 `mode=external`，`static_result=external_control`；仍須完成控制責任及外部缺口裁決。
- `external_responsibility_pending`：僅限 `static/hybrid`；已取得**真實的委外控制責任歸屬**，但不能從儲存庫確認外部控制是否生效。設 `static_result=delegated_control`、`static_evidence=[]`、列出真實 `searched_paths`，並提供 `responsibility_evidence`、具體 `responsibility_reason` 和 `repository_search_summary`。責任證據必須對應正式 `checks[].evidence` 的來源行號或實際外部工件 `artifact_id`；不可用泛稱政策、未取得的文件或套件宣告充數。仍須以 `external_gap` 列出確實會改變判定的外部工件、負責單位與雙向結果。
- `pass` 的控制完全由外部平台執行且已經核實時，可在 `analysis/control-verifications.json` 記錄 `control_proof_mode=external_verified`，另附已存在於正式檢核證據的 `responsibility_evidence` 與 `control_evidence`、實際控制條件、失效行為、全規則指定繞過情境及來源快照版本。**已證實責任歸屬不等於已證實控制有效**；找不到外部控制運作證據時不得標 `pass`。
- 來源已證明弱點仍為 `fail` ＋ Finding；無法確認委外責任或尚未完成必要搜尋時為 `pending/blocked`。不因缺證據機械改成 `review`、`na` 或 `pass`。

外部責任已被驗證時，Q2／Q3 不要求虛構本地程式碼控制點，但跨檔候選、呼叫點、結案責任、來源覆蓋、證據日誌與第二輪仍須完整驗證。以上只是工具契約格式；是否確實委外及外部工件內容是否有效仍須由主代理實際核對。

## 全 70 項的外部缺口決定性驗證

新版 `analysis_prepare.py --mode full` 產出的結構索引包含 `decision_quality_version=1`。在保留既有判定驗證之外，**每個完成的 Review** 都必須說明外部資料如何真正改變判定，不因 AC-01 等個別規則而特殊放行。

- `external_gap.artifact` 必須是具體工件；禁止 `AC-01-deployment-or-policy-evidence`、`相關文件`、`<policy>` 等佔位符。純粹欠缺動態測試仍不能構成 Review。
- `external_gap.evidence_owner` 記錄可向何單位或平台取得證據，不得自行臆造已持有的文件。
- `external_gap.decision_outcomes` 必須具備 `if_satisfied` 與 `if_unsatisfied`，各自包含 `status`（pass／fail／na）及具體 `reason`。兩個分支若結果相同，該外部缺口並不阻斷判定，不能保留 Review。
- 對 `organization_policy`，額外要求 `external_gap.policy_binding.reference` 與 `applicability_reason`，說明**已知**適用於受測系統的正式政策識別及依據。若只是推測「也許有更嚴格的內部政策」，不能用它阻擋已可由程式碼判定的基本控制。
- 靜態證據必須列於實際搜尋路徑；Review 文字／Finding 已明示確認缺陷時，必須重新裁決為 Fail＋Finding，不能把缺少政策文件當成藉口。
- 這些檢查是**輸入品質守門**，不能證明資料真偽，也不會自動把 Review 改成 Pass／Fail；必要時維持 `pending/blocked` 補查。

合格的 `external_gap` 擴充範例（工件名稱、適用政策及推論皆是**示範**，不可直接複製作為真實專案證據）：

```json
{
  "category": "organization_policy",
  "artifact": "組織正式 Session 最長有效期限核定文件",
  "evidence_owner": "資訊安全管理單位",
  "blocking_question": "已核定的最大有效期限是否允許此系統實作值",
  "why_decisive": "伺服端已核對有拒絕過期票據的控制，但政策若規定更短期限則不符合",
  "manual_boundary": "逾時長度是否符合組織政策",
  "policy_binding": {
    "reference": "示例-ISMS-SESSION-2026",
    "applicability_reason": "假設已有文件明確將本系統列入指定逾時期限的強制適用範圍"
  },
  "decision_outcomes": {
    "if_satisfied": {
      "status": "pass",
      "reason": "如核定期限容許目前服務端設定，且已確認逾時會拒絕請求，則符合"
    },
    "if_unsatisfied": {
      "status": "fail",
      "reason": "如核定期限短於目前伺服端有效期限，則應建立不符合的 Finding"
    }
  }
}
```

**特別注意 AC-01：** 規則的基本 `pass_condition` 是「有效期限由伺服端驗證且逾期不可使用」；不得把「缺少絕對期限／組織政策」當成自動 Fail 或 Review。要先區分伺服端基本期限、前端閒置倒數及正式政策要求，確認每條控制是否真的有效；若控制有明確弱點，優先 Fail。

既有 `decision_quality_version` 缺席的結構索引保留原有判定裁決契約，不會靜默重寫報告。**重新掃描以啟用此功能時**，須執行 `analysis_prepare.py --mode full`、更新來源快照並依法重審已完成判定；新版守門可能拒絕尚未補齊判定品質證據的舊 Review，但不會刪除 Finding 或自動改判。

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
        "manual_boundary": "逾時長度是否符合組織政策",
        "evidence_owner": "資訊安全管理單位",
        "policy_binding": {
          "reference": "示例-ISMS-SESSION-2026",
          "applicability_reason": "此示例假設已確認受審系統須遵循指定的核定期限政策"
        },
        "decision_outcomes": {
          "if_satisfied": {
            "status": "pass",
            "reason": "若核定期限允許目前服務端設置且有效拒絕逾期請求，則符合"
          },
          "if_unsatisfied": {
            "status": "fail",
            "reason": "若核定時效短於現行服務端可持續有效期限，則存在不符合情況"
          }
        }
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
