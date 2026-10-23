# 單代理第二輪反向複核與矛盾裁決

此程序要求**單一主代理執行兩個分離階段**：先完成 70 項規則與 100% 來源查核，再重新閱讀程式碼，以攻擊者視角挑戰先前結論。這不是另一個獨立模型或盲審員；相同代理仍可能有共同偏誤，不能將第二輪通過宣稱為真正的獨立稽核。

## 執行順序與完成條件

1. 第一輪照既有 SKILL 流程，逐項完成 70 項規則、逐檔 10 類評估、P1 跨檔閉包、控制有效性查核、review 外部證據裁決，以及 Finding／來源快照確認。**不得先填第二輪紀錄再補做第一輪**。
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

## 限制與相容性

- 不新增並行代理，不宣稱具真正獨立性；同一模型重讀仍有系統性盲點。
- 不修改受測專案原始碼、不放寬原 70 項與 100% 來源覆蓋、不改動正式 assessment Schema／HTML／JSON。
- 使用工作中 JSON 儲存第一輪錨點與第二輪證據；來源／Git 版本異動時，舊錨點與複核證據會失效，不能僅改雜湊冒稱已重審。
- 第二輪不可用非必要測試缺口替代既有判定階梯，確認的缺陷仍須 `fail`＋Finding。
- 自動守門只驗證資料和行號可追溯，無法證明第二輪真的推翻所有可能反例；實際安全判定仍由代理閱讀分析原始碼。
