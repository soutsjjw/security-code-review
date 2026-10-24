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
- 來源檔或 Git Revision 異動會拒絕重用先前快照／已完成規則；不得刪除 Finding 或強行重設以繞過。須核對變更與原有資料後採取明確的重新審查／重建策略，不能假稱已有自動修復或跨版本自動續用功能。
- 分類報告的多檔案發布具備可捕獲寫入失敗時的回滾機制，但**不是作業系統級交易**；若強制終止、斷電、發布鎖或備份異常，應先核對資料，不可刪除可能仍須復原的檔案。
- 同一類別重新執行須沿用其已保存進度與 Finding，來源版本有效時不重置。只有明確未指定 `--categories` 時，才採完整 70 項正式流程。

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
