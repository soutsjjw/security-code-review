# 分類資安審查操作契約（Codex／Claude Code）

## 執行模式與受測範圍

本文件僅適用明確輸入 **`--categories`** 的情況。Agent 必須先解析使用者輸入，再選擇唯一的流程，不可同時執行完整／分類兩套初始化與報告指令：

| Skill 輸入 | 模式 | 驗證與報告 |
|---|---|---|
| `$security-code-review` | 完整審查 | 正式 70/70、10 類逐檔篩選、正式 HTML／JSON |
| `$security-code-review --categories AC` | 部分審查 | 只判定 AC 8 項；`partial/AC/` |
| `$security-code-review --categories AC,AU` | 部分審查 | AC 8 項、AU 10 項，各自驗證及輸出 |
| `$security-code-review --categories AC,AU,IN,CR,EH,LG,DP,PD,BC,SI` | 部分審查 | 十份各分類報告，**不是**正式完整報告 |

- 類別與規則數固定：AC 8、AU 10、IN 8、CR 6、EH 6、LG 10、DP 4、PD 8、BC 7、SI 3，原始 `rules.json` 仍包含全部 70 項。
- `--categories` 僅提供一次，逗號分隔、不重複、不接受未知分類；大小寫及逗號旁空格由 `review_scope.py` 正規化，順序依正式規則主檔。
- **用戶在 Codex App 的對話中輸入 Skill 名稱及文字參數**，不是要用戶在 PowerShell 呼叫名為 `$security-code-review` 的命令，也不是 Python 腳本直接解析 Codex Prompt。
- 若有指定受測專案路徑，Agent 將之解析為 `TARGET_ROOT`，確認存在、位於受測工作樹而非 `SKILL_ROOT`。只有模糊的子目錄／文件描述時，先保持目前專案為目標根目錄，不得把 Skill 安裝目錄當成受測內容。
- 指定分類**縮小的是規則判定集合**，不是來源掃描範圍：Controller、Handler、Service、Repository、Identity、Middleware、設定、DI、跨專案引用等必要關聯都要讀取。所有應審查來源檔都要完成所選分類的逐檔適用性篩選。
- 完整模式沿用 `SKILL.md` 的正式 70 項流程；本頁其餘指令**不得**被加入完整模式的正式審查佇列。

## 分類審查不可放寬的證據要求

同一主代理逐檔追查、完成實際安全判定及第二輪自我複核，**不用子代理或平行填報**：

1. 每條選定規則須讀取 `--detail-id` 的完整標準對照、判定矩陣、控制有效性與反例指引。索引／CodeGraph／Roslyn 只用來定位，不能當作安全結論。
2. 逐檔產生 `file_reviews[]`，`category_screening` **僅含當前分類**；若規則適用，`rule_reviews` 逐條與該檔來源行號、`execution.inspected_paths`、Finding 對應。當次所選分類的應審查來源覆蓋率必須為 100%。
3. `pass` 須實際確認安全控制的入口、執行、拒絕分支、受保護操作及繞過；`fail` 建立真實 Finding；`review` 僅保留已查完靜態部分且確實必要的具體外部工件缺口；`na` 記錄已核對的控制責任。未完成來源追查時保持 `pending/blocked`，不得以 `review` 假裝完成。
4. `cross_file/project` 規則完成 `closures`；符合條件的規則補 `control_verifications`、`decision_audits`。資料欄位使用 [跨檔守門](review-integrity-guards.md)、[安全控制](control-effectiveness-review.md)、[待確認裁決](review-decision-adjudication.md) 的**同一契約**。
5. 分類第一輪完成且 分類安全守門通過，才能針對**該分類**建立固定基準。主代理重新閱讀來源、逐條提出可反駁的攻擊假設，留下 `adversarial_reviews` 與必要矛盾裁決。已完成判定不可無條件覆寫；必要修訂須以 `--allow-revision` 和真實證據保留歷史，已證實 Fail 不可降級。
6. 不得利用第二輪、完整來源清單或某個分類的完成紀錄自動給其他分類 `completed/pass/na`；不因候選索引或 JSON Schema 通過就宣布弱點不存在。

## 操作順序（Agent 執行，使用者只需一次 Prompt）

以下範例中 `CATS=AC,AU` 代表本次指定類別；操作時 Agent 必須將 `<SKILL_ROOT>`、`<TARGET_ROOT>` 替換為真實路徑，並透過 Skill 提供的 Python 啟動器執行。先執行 `--check` 確認 Python 3.10+ 與相依套件。

| 動作 | 完整指令中的附加參數 |
|---|---|
| 解析分類及正式規則清單（唯讀） | `review_scope.py --target "<TARGET_ROOT>" --categories AC,AU` |
| 初始化分類資料（僅新增） | `review_queue.py --target "<TARGET_ROOT>" --categories AC,AU --init --compact` |
| 建立或重用**分類共用**來源索引 | `review_queue.py --target "<TARGET_ROOT>" --categories AC,AU --prepare` |
| 查詢下一批分類待辦 | `review_queue.py --target "<TARGET_ROOT>" --categories AC,AU --compact` |
| 取得一條完整規則指引 | `review_queue.py --target "<TARGET_ROOT>" --categories AC --detail-id AC-01` |
| 暫存某分類真實分析證據 | `review_queue.py --target "<TARGET_ROOT>" --categories AC --stage "<AC_BATCH>.json"` |
| 整合該分類暫存證據 | `review_queue.py --target "<TARGET_ROOT>" --categories AC --integrate` |
| AC 第一輪完全結案後固定第二輪基準 | `review_queue.py --target "<TARGET_ROOT>" --categories AC --begin-second-pass` |
| 整合第二輪真實證據 | `review_queue.py --target "<TARGET_ROOT>" --categories AC --stage "<AC_SECOND_PASS>.json"`，再執行 `--integrate` |
| 檢查 AC 與 AU 的 分類安全守門 | `review_queue.py --target "<TARGET_ROOT>" --categories AC,AU --validate` |
| 唯讀彙總各類驗證缺漏與待補來源 | `review_queue.py --target "<TARGET_ROOT>" --categories AC,AU --diagnose` |
| 第一輪既有證據經審查後明確補正 | `review_queue.py --target "<TARGET_ROOT>" --categories AC --integrate --amend-first-pass` |
| 各分類產生自己的 HTML／JSON | `complete_review.py --target "<TARGET_ROOT>" --categories AC,AU` |
| 嚴格驗證已產生的兩份報告 | `validate_report.py --source-root "<TARGET_ROOT>" --strict-sources --categories AC,AU` |

Windows PowerShell：

```powershell
& "<SKILL_ROOT>\scripts\run-python.cmd" --check
& "<SKILL_ROOT>\scripts\run-python.cmd" "<SKILL_ROOT>\scripts\review_scope.py" --target "<TARGET_ROOT>" --categories AC,AU
& "<SKILL_ROOT>\scripts\run-python.cmd" "<SKILL_ROOT>\scripts\review_queue.py" --target "<TARGET_ROOT>" --categories AC,AU --init --compact
& "<SKILL_ROOT>\scripts\run-python.cmd" "<SKILL_ROOT>\scripts\review_queue.py" --target "<TARGET_ROOT>" --categories AC,AU --prepare
```

macOS／Linux：

```bash
sh "<SKILL_ROOT>/scripts/run-python.sh" --check
sh "<SKILL_ROOT>/scripts/run-python.sh" "<SKILL_ROOT>/scripts/review_scope.py" --target "<TARGET_ROOT>" --categories AC,AU
sh "<SKILL_ROOT>/scripts/run-python.sh" "<SKILL_ROOT>/scripts/review_queue.py" --target "<TARGET_ROOT>" --categories AC,AU --init --compact
sh "<SKILL_ROOT>/scripts/run-python.sh" "<SKILL_ROOT>/scripts/review_queue.py" --target "<TARGET_ROOT>" --categories AC,AU --prepare
```

**注意**：

- 分類模式用 `review_queue.py --prepare` 建立 `partial/_shared/analysis/structure-index.json`，**不得用正式模式的 `analysis_prepare.py` 替代**，以免不必要地修改正式 `analysis/` 狀態。
- 分類 `--stage`／`--integrate`／`--begin-second-pass` 每次限一個分類，須分別處理 AC、AU。單一批次 JSON 只包含該分類的 `checks`、`file_reviews`、`findings`、`closures`、`control_verifications`、`decision_audits` 或 `adversarial_reviews`。根據當次真實工作填寫，不得預填或偽造結論。
- 第一輪與第二輪都須實際完成；`review_queue.py` 在分類模式下**始終**回傳 `ready_for_report=false`，這是保護正式報告的設計。**分類完成條件**為每一分類的 `safety_valid=true`、`safety_integrity_errors=[]`、`remaining_ids=[]`、`second_pass.pending_count=0`，且分類 `complete_review.py` 和 `validate_report.py` 均成功，不能以 `ready_for_report=true` 判斷部分模式。
- 分類 `--validate` 尚有未解證據時會退出碼非 0；應讀取實際錯誤繼續查核，**不能因驗證失敗而填假資料**。某分類未完成時，不產生該分類的成功報告。
- 若顯示 `integrity-pending.json` 未完成，先保留 staged、Finding 與 Journal，核對來源與證據後，對**該單一分類**執行 `review_queue.py --target "<TARGET_ROOT>" --categories AC --recover-integrity`。復原會先比對原始／目標 SHA256、Journal、staged 及來源版本；第三種內容或不明中斷一律拒絕，不得刪除 pending 強行續跑。詳細說明見 [分類證據交易完整性](category-integrity.md)。
- 來源檔或 Git Revision 異動會拒絕重用先前快照／已完成規則；不得刪除 Finding 或強行重設以繞過。須核對變更與原有資料後採取明確的重新審查／重建策略，不能假稱已有自動修復或跨版本自動續用功能。
- 分類報告的多檔案發布具備可捕獲寫入失敗時的回滾機制，但**不是作業系統級交易**；若強制終止、斷電、發布鎖或備份異常，應先核對資料，不可刪除可能仍須復原的檔案。
- 同一類別重新執行須沿用其已保存進度與 Finding，來源版本有效時不重置。只有明確未指定 `--categories` 時，才採完整 70 項正式流程。

## 第一輪已完成紀錄的受控補正（不必 archive／重建）

當 Manifest／Journal 鏈有效、沒有 pending 交易，但 `--validate` 顯示既有 `completed` 的安全證據、逐檔覆蓋或跨檔關聯不足時：

1. 先執行 `review_queue.py --target "<TARGET_ROOT>" --categories AC,AU --diagnose`。唯讀回傳 `error_types`、`errors_by_rule`、`source_coverage.missing_source_paths` 與第二輪狀態；診斷成功**不代表安全驗證通過**。若仍有未封存／損壞交易，先依完整性契約處理，不能用補正繞過。
2. Agent 依缺漏重新閱讀實際來源、查完跨檔呼叫鏈、控制有效性與真實繞過情境，必要時補全 `file_reviews`、`checks.execution.inspected_paths`、`closures`、`control_verifications`、`decision_audits`。未修改既有證據的新增待辦仍使用一般 `--stage/--integrate`。
3. **只有第一輪 baseline 尚未建立**、需要修訂既有 `completed` 判定或已保存的逐檔／安全證據時，將修訂資料與 `first_pass_amendments` 一併寫入**同一分類** batch JSON。每個受影響規則都須提供至少一筆真正核實的來源位置與具體補正理由。例如（hash、路徑與程式碼片段均須換成實際值）：

```json
{
  "first_pass_amendments": {
    "AC-01": {
      "reason": "已重新檢查登入端點與授權控制流程，補正先前缺漏的跨檔控制鏈及逐檔證據。",
      "source_evidence": [
        {
          "path": "src/Identity/IdentityService.cs",
          "sha256": "<該檔案真實 SHA256>",
          "line_start": 45,
          "line_end": 45,
          "excerpt": "<該行實際存在的至少八字元程式碼>"
        }
      ]
    }
  },
  "checks": [
    "<此處放完整且具真實證據的 AC-01 check 物件，不得填字串模板>"
  ],
  "closures": {
    "AC-01": "<此處放完整的跨檔查證紀錄>"
  }
}
```

   實際 `checks`、`closures` 須為原契約要求的 JSON 物件，以上僅說明欄位結構，**不可直接送入 stage**。來源 `path` 必須在當次固定快照，`sha256` 與磁碟檔案相符，`line_start/line_end` 有效，`excerpt` 必須確實出現在指定行。
4. 先呼叫 `review_queue.py --target "<TARGET_ROOT>" --categories AC --stage "<BATCH>.json"`；再明確呼叫 `review_queue.py --target "<TARGET_ROOT>" --categories AC --integrate --amend-first-pass`。AU 必須各自執行，**不可**搭配 `--allow-revision`。原版與補正說明以同一筆 Journal 交易封存到 `analysis/first-pass-corrections/<32hex>.json`。
5. 只有實際修改的規則／舊證據才可出現在 `first_pass_amendments`；修訂同一檔既有 `file_reviews`，必須核實該檔內容並列出被修改的關聯規則。既有 Fail 不可變成非 Fail、既有 Finding 關聯不可移除；改為 Fail 必須有可追查 Finding。原 `assessment.json`、安全證據、Manifest、Journal 均不得直接編輯。
6. 補正後重新 `--validate`。第一輪全部通過才可 `--begin-second-pass`，之後仍使用既有 `--allow-revision` 第二輪流程及原本的嚴格報告驗證。

**非補正情境**：來源或 Git Revision 變動、交易 hash 異常、Manifest 消失、Journal 不一致、已有 baseline，均不得使用 `--amend-first-pass` 當成快速重封存。真實補正只解決審查證據不足，不能取消需要做的靜態分析與第二輪反例核對。

## 交付格式與目錄

```text
<TARGET_ROOT>/reports/security-code-review/
├── assessment.json                 # 完整模式 70 項（分類不覆寫）
├── report.json                     # 完整模式正式報告（分類不覆寫）
├── CodeReview_YYYYMMDD.html        # 完整模式正式報告（分類不覆寫）
└── partial/
    ├── _shared/analysis/           # 分類共用來源候選索引與完整性資訊
    ├── AC/
    │   ├── assessment.json         # 僅 AC 8 項
    │   ├── analysis/               # AC 跨檔、安全控制、判定、第二輪證據
    │   ├── report.json
    │   └── CodeReview_YYYYMMDD.html
    └── AU/
        ├── assessment.json         # 僅 AU 10 項
        ├── analysis/
        ├── report.json
        └── CodeReview_YYYYMMDD.html
```

每個分類的 HTML 標示「**部分審查**」，列出所選規則、逐條證據、Finding 及來源覆蓋；其他分類沒有安全判定，不能把十份部分報告拼接後宣稱為正式 70 項審查。最終答覆列出各分類規則完成數、Finding、HTML／JSON 路徑及仍有的外部證據限制。不能用規則主檔、無證據的自動完成或靜態分析候選作為已完成的替代品。
