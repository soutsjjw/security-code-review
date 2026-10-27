# 第二輪反向複核與矛盾裁決

此程序要求**單一主代理負責兩個分離階段及最終裁決**：先完成 70 項規則與 100% 來源查核，再重新閱讀程式碼，以攻擊者視角挑戰先前結論。預設同一代理可能有共同偏誤；僅在已完成 [受控多代理 受控多代理](multi-agent-review.md) 的能力試跑後，可另讓唯讀子代理在不知道第一輪結論的情況下提出反例，但仍不能稱為獨立稽核或替代主代理重讀。

## 執行順序與完成條件

1. 第一輪照既有 SKILL 流程，逐項完成 70 項規則、逐檔 10 類評估、跨檔關聯與控制責任結案、控制有效性查核、review 外部證據裁決，以及 Finding／來源快照確認。**不得先填第二輪紀錄再補做第一輪**。
2. 在受測專案目錄執行：
   ```bash
   python "<SKILL_ROOT>/scripts/review_safety.py" --target "<TARGET_ROOT>" --begin-second-pass
   ```
   這會在正式檢核全部 completed、現有來源與規則完整性驗證通過後，寫入 `analysis/first-pass-baseline.json`，固定每條規則的**狀態與完整判定摘要**以及完整來源快照指紋。再次執行相同內容可安全重試；若結果不同，必須人工查明，不可靜默覆蓋原始判定。
3. 第二輪重新開啟來源，不沿用第一輪的「結論敘述」作為新證據，對每條規則提出至少一個反例假設；高風險控制（如 AC-01、AC-08、AU-08、IN-01、IN-07）至少兩個**不同攻擊面**。重新確認入口、分支、DI、組態覆寫、授權主體與查詢條件，實際核對反例及相反結果。
4. `review_queue.py --target "<TARGET_ROOT>" --compact` 會提供 `second_pass.baseline_ready`、`pending_count`、`pending_ids` 及進度；`--detail-id <RULE_ID>` 有 `adversarial_guidance` 指出最低反例數量。這些是待複核工作，不會增加 70 項規則，也不會把原本 completed 改成 pending。
5. 每批將第二輪紀錄置於原有 `review_safety.py --stage` JSON 的 `adversarial_reviews`，經 `--integrate` 以單一寫入者儲存於 `analysis/adversarial-reviews.json`。**不得**只將第一輪理由重新表述或填固定模板。
6. 第二輪發現第一輪錯誤：先依法建立／保留 Finding，修訂規則狀態、證據和必要工作中紀錄；對完成判定的合法修訂使用 `--allow-revision`，保留第一輪快照不修改。第二輪紀錄填 `outcome=corrected`，以 `contradictions` 明確寫出最初與修訂後的狀態、來源行號、裁決理由。若未解決，停止正式結案，保留進度。
7. 所有 70 項第二輪證據通過 `review_safety.py --validate`，`review_queue.py` 回傳 `ready_for_report=true` 後才能呼叫 `complete_review.py`。未修訂的規則應記 `outcome=confirmed` 且 `contradictions=[]`，若修改規則結論／證據卻沒有裁決紀錄，會被擋下。

## 工作中 JSON 結構

以下只示範**欄位形狀**，不代表實際來源已查核；所有摘要指紋、Git 快照與行號必須來自當次受測資料：

```json
{
  "adversarial_reviews": {
    "AC-08": {
      "baseline_digest": "<first-pass-baseline.json 中 AC-08 的 digest>",
      "final_digest": "<目前正式 AC-08 完整檢核內容的 digest>",
      "final_status": "pass",
      "snapshot_fingerprint": "<first-pass-baseline.json 的 snapshot_fingerprint>",
      "outcome": "confirmed",
      "attacker_perspective": "說明若攻擊者改變物件 ID、身分主體或直接呼叫服務會如何試圖繞過",
      "search_summary": "說明本次重新閱讀的入口、服務分派、查詢分支與實際檢查方法",
      "hypotheses": [
        {
          "attack_surface": "horizontal_idor",
          "attempt": "說明是否存在只依物件 ID、未依登入主體過濾的另一條資料查詢路徑",
          "result": "blocked",
          "evidence": {
            "kind": "source",
            "path": "src/Orders/OrderService.cs",
            "line_start": 42,
            "line_end": 44
          }
        }
      ],
      "contradictions": [],
      "open_issues": []
    }
  }
}
```

**此 AC-08 示例故意只列一個假設，尚不符合其兩個不同攻擊面要求，不可直接用於結案。**

反例狀態：`blocked`、`confirmed_vulnerability`、`external_boundary`、`not_applicable`。結果必須與正式判定一致：`pass` 不能附未解的漏洞；`fail` 必須有仍存在的 Finding；`review` 要引用現有裁決紀錄中的真正外部缺口（`evidence.kind=external_gap`）；`na` 必須查明不適用範圍。程式碼證據路徑必須在快照和 `inspected_paths`，行號必須真實有效。若第二輪發現需要追查原先未檢查的檔案，應先補充原規則的 `inspected_paths` 並重新整合正式結果，再建立新的第二輪紀錄。

## 實質反向複核品質守門（全部 70 項）

新版 `structure-index.json` 包含 `adversarial_quality_version=1`，並在原有不可變第一輪錨點中額外保留 `checks[rule_id].decision_reason`，讓第二輪能針對**第一輪真正主張**提出可反駁的質疑，而非只核對 Pass／Fail 狀態。這不代表啟用了另一個獨立代理。

以下均屬現有 `adversarial_reviews[rule_id]` 工作中證據的新增欄位，**不修改正式 assessment Schema**：

- **舊版 Baseline 相容模式**的 `reassessment.first_pass_claim`：須逐字對應不可變第一輪判定理由；新分層模式改用 `blind_challenge` 事實主張先行，正式裁決仍須與不可變 Baseline 對帳。`challenge_question` 指出可能推翻判定的具體條件；`reinspection_summary` 記錄再次查閱的入口、分支、DI／設定；`conclusion_basis` 說明為何維持或修訂；`verification_evidence` 必須能重新定位至已查核來源或真正外部工件。
- 每個 `hypotheses[]` 除原有攻擊面、追查方法、結果及來源外，新增 `vector`、`attacker_precondition`、`expected_violation`、`inspection_steps`、`observed_behavior`、`inspection_evidence`。分別回答**攻擊者需具備什麼、試圖破壞什麼、實際重讀哪一個分支、查核後看到什麼**。僅更換規則編號或序號、重複同一攻擊敘述，不算不同反例。
- `vector` 應選具體攻擊類別，包括 `alternate_entry`、`authorization_bypass`、`identity_substitution`、`expired_or_reused_credential`、`configuration_override`、`direct_storage_access`、`untrusted_input`、`output_encoding`、`state_change`、`exception_path`、`dependency_injection`、`third_party_boundary`、`operational_override`、`scope_challenge`；`other_specific` 需另附 `vector_explanation`。高風險規則仍需至少兩個**不同 vector**。
- `evidence` 指向攻擊入口或缺失，`inspection_evidence` 指向重新閱讀的控制或拒絕分支。若兩者恰好同一來源行，提供 `same_line_explanation`（具體說明同一行如何承擔兩種責任）；若兩個高風險反例都用完全相同證據組，補 `shared_evidence_justification` 說明不同攻擊如何匯入共同控制。
- 不同規則如共用相同攻擊前提、預期破壞、查核結果或同一來源行，驗證器會偵測模板化紀錄。真正存在共享安全控制時，需逐規則說明控制關聯，例如 `cross_rule_proof_justification`；不可用「已檢查各項安全機制」之類制式理由。
- `outcome=corrected` 另需在每個 `contradictions[]` 提供 `why_first_pass_missed` 與 `corrective_action`，說明最初漏查的路徑、重新裁決與處理方式。若第二輪由非 Fail 改為 Fail，具體 `confirmed_vulnerability` 的來源必須和**此規則的 Finding 證據**重疊，不允許只有狀態修改。

以下是**欄位示例**，行號與內容不可直接套用成正式查核成果：

```json
{
  "reassessment": {
    "first_pass_claim": "<不可變第一輪 decision_reason 原文>",
    "challenge_question": "若可透過另一入口直接存取資料，原本的物件擁有者授權是否仍能生效",
    "reinspection_summary": "說明第二輪重新開啟 Controller、Service、Repository 的實際位置與分支",
    "conclusion_basis": "說明在另一條入口下，控制如何實際拒絕或為何發現缺失",
    "verification_evidence": {
      "kind": "source", "path": "<真實服務檔案>", "line_start": 42, "line_end": 42
    }
  },
  "hypotheses": [{
    "attack_surface": "direct_order_lookup",
    "vector": "direct_storage_access",
    "attacker_precondition": "描述能指定他人訂單識別值並繞過正常 UI 呼叫的前提",
    "expected_violation": "描述若未檢查主體擁有者資訊將如何取得他人訂單",
    "inspection_steps": "描述重新閱讀的直接查詢、授權分支和 Repository 呼叫",
    "observed_behavior": "描述真實程式碼中有無擁有者驗證及會執行的查詢條件",
    "attempt": "描述此入口的反例重現方式",
    "result": "blocked",
    "evidence": {
      "kind": "source", "path": "<真實入口檔案>", "line_start": 20, "line_end": 20
    },
    "inspection_evidence": {
      "kind": "source", "path": "<真實服務檔案>", "line_start": 42, "line_end": 42
    }
  }]
}
```

注意：這不是完整 `adversarial_reviews`，且 AC-08 高風險規則需兩個不同攻擊向量，不能以此片段結案。部署／制度型規則可沿用已有的 `external_gap`／`external_artifact` 真實工件做反向查證，**不得捏造程式碼鏈**。第一輪未儲存判定理由的舊錨點不會自動被補寫；必須人工確認後依原有 `--restart-second-pass` 歸檔及重建程序處理。驗證器無法憑文字、行號證明執行者真的重新閱讀程式碼，仍需在實際審查中驗收。

## 分層第二輪（完整 70 項模式）

第一輪仍須 70 項與 100% 應審查來源完整驗證；**第二輪不再以完整來源樹重新掃描為工作方式**。這個模式僅減少第二輪重複讀檔，不改變安全判定及正式交付守門。分類模式維持原有各分類第二輪契約。

1. `--begin-second-pass` 於新 Baseline 一併在既有受控 `analysis/adversarial-reviews.json` 寫入 `__layered__.plan`。計畫含 70 項的事實性來源錨點（行號、檔名），**不提供** `status`、置信度或第一輪 `decision_reason`。保留原 Baseline 作最後對帳；同一主代理仍不算真正盲審。
2. Agent 唯讀執行 `python "<SKILL_ROOT>/scripts/second_pass_layers.py" --target "<TARGET_ROOT>"` 取得 `rule_tasks`、`sample_tasks`、`targeted_paths` 與 `budgets`。每批預設最多 8 項規則、16 個錨點來源檔、4 個抽樣檔。輸出的 `token_hint_per_batch=30000` 是建議上限，**並非**可由 Python 強制量測代理 Token；使用執行器可取得的真實 Token 記錄，超出時結束本批、保存進度，再查下批，不能判定已完成。
3. 70 項仍各自要有原本反向複核反例與有效控制證據；新計畫啟用時每個 `adversarial_reviews[rule_id]` 額外帶 `blind_challenge`：`factual_claim`、`challenge_question`、`initial_observation`（各為實際來源描述）、`evidence`（已核實來源位置）。先從錨點觀察事實並提出可推翻問題，**最後**才比對第一輪結論並填 `reassessment`、`outcome`、`contradictions`。不得把第一輪整段判定當作事實性主張。
4. 計畫按固定來源快照指紋、風險檔名訊號與可重現順序，選出第一輪正式 evidence **未引用**的入口、身分授權、設定、外部輸入與錯誤分支。這些是風險抽樣，不代表未引用路徑第一輪未讀；來源檔名只是選樣訊號，不能當作安全結論。預設最多 24 檔、候選約 10%，若無合格候選則樣本為空且保留候選數。
5. 每個樣本由主代理真正讀取，透過 `review_safety.py --stage <JSON>`、`--integrate` 寫入受控資料。暫存 JSON 的 `second_pass_samples` 以**計畫中的檔案相對路徑**為鍵，每筆需 `outcome`（`no_new_issue`、`confirmed_vulnerability`、`not_applicable`）、具體 `inspection_summary`、`evidence`（同路徑實際來源行號）。新漏洞還需先建立正式 Finding 並以 `finding_id` 關聯；不能只記錄一段掃描摘要。範例（僅示意，不可照填未讀證據）：

   ```json
   {
     "second_pass_samples": {
       "src/Auth/AccessController.cs": {
         "outcome": "no_new_issue",
         "inspection_summary": "此處需填本次真實閱讀的入口與有效分支、核對結果及未發現缺口的依據",
         "evidence": {
           "kind": "source", "path": "src/Auth/AccessController.cs",
           "line_start": 42, "line_end": 47
         }
       }
     }
   }
   ```

6. 所有固定樣本必須完成實際裁決才可正式 `--validate`／產生報告。來源或 Baseline 改變時走既有合法更正與 `--restart-second-pass` 流程，不得替換樣本消除弱點；預算用完只暫停並 checkpoint，不准改 `completed` 或刪除 Findings。需要追查樣本外新的跨檔控制時，可**有界延伸追查**並分批保存正式證據，不能依靠樣本比例迴避已知缺口。

## 限制與相容性

- 不新增並行代理，不宣稱具真正獨立性；同一模型重讀仍有系統性盲點。
- 不修改受測專案原始碼、不放寬原 70 項與 100% 來源覆蓋、不改動正式 assessment Schema／HTML／JSON。
- 使用工作中 JSON 儲存第一輪錨點與第二輪證據；來源／Git 版本異動時，舊錨點與複核證據會失效，不能僅改雜湊冒稱已重審。
- 若來源或已完成的第一輪結果改變，須先依法重新審查並通過完整性守門，再**明確**執行 `review_safety.py --restart-second-pass`；工具會把原第一輪快照與第二輪紀錄保存至 `analysis/second-pass-history/`，並清空目前複核紀錄以要求 70 項重新複核。沒有 `--restart-second-pass` 不會覆寫舊第一輪快照，歷史複核資料也不會刪除。
- 第二輪不可用非必要測試缺口替代既有判定階梯，確認的缺陷仍須 `fail`＋Finding。
- 自動守門只驗證資料和行號可追溯，無法證明第二輪真的推翻所有可能反例；實際安全判定仍由代理閱讀分析原始碼。
