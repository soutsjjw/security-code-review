# 分類證據完整性與受控交易

分類審查採用每個分類獨立的 Manifest、SHA256 Journal 與預寫交易。完整 70 項審查保留既有資料及交易流程。

## 目錄與契約

```text
reports/security-code-review/partial/<CAT>/
├── assessment.json
├── project.json
└── analysis/
    ├── source-snapshot.json
    ├── rule-closures.json
    ├── control-verifications.json
    ├── decision-audits.json
    ├── adversarial-reviews.json
    ├── first-pass-baseline.json
    ├── second-pass-history/<32hex>.json
    ├── integrity-manifest.json
    ├── integrity-pending.json
    ├── integrity-journal/
    │   ├── 00000000.json
    │   └── 00000001.json
    ├── integrity.lock
    └── staged/pending.json
```

- `source-snapshot.json` 鎖定來源 Git Revision／SHA256；共用索引位於 `partial/_shared/analysis/`，不混入分類證據交易。
- Manifest 記錄分類、來源快照、序號與最新 Journal SHA256；每筆 Journal 記錄上筆 hash 與提交後各受控檔案原始 bytes 的 SHA256。
- 固定檔案缺少時記錄 `null`；第二輪修訂歷史採動態清單，新增、刪除、修改都須納入完整性驗證。
- 每次分類 `stage` 取得分類鎖、檢查完整性，再保存待整合批次；全新且乾淨的分類進度可自動建立初始封存。已有完成結果、Finding、逐檔或第二輪證據的舊資料，需要人工核對後明確封存，**不能自動信任**。
- `integrate` 驗證批次、版本與 Finding 限制後，於同一分類鎖內先落盤 `integrity-pending.json`（包含更新目標、舊／新 SHA256、來源快照及 staged SHA256），再依序原子更新證據與 `assessment.json`，核對各檔案並提交 Journal 與 Manifest，成功後才刪除 staged 與 pending。
- 第一輪固定基準也透過受控交易提交；已完成的判定修訂歷史會在同筆交易中保存，不能靜默降低已證實的 Fail。
- 使用排他 `integrity.lock` 拒絕同分類並行更新；不會自動刪除未知交易鎖，AC、AU 完全隔離，也不能改寫正式 70 項審查資料。
- SHA256 可辨識意外及流程外修改，但無外部信任錨點時不是抵抗完全控制儲存空間攻擊者的數位簽章。

## 內部 API

```python
from partial_evidence_integrity import initialize, errors, locked, commit

initialize(target_root, "AC")                 # 初始乾淨分類進度
initialize(target_root, "AC", explicit=True)  # 既有資料人工核對後明確封存
problems = errors(target_root, "AC")          # 唯讀核對
with locked(target_root, "AC"):
    pass
```

一般工作由 `review_queue.py --categories AC --stage`、`--integrate` 驅動，Agent 不必直接呼叫內部 commit API。

## 中斷復原操作

當分類整合寫入中斷時，`integrity-pending.json`、Journal、已更新的證據和 staged 檔案會留下。此時 stage、integrate、安全驗證與報告交付都會**拒絕成功**，不得藉刪除檔案繞過完整性守門。

復原必須**明確指定單一分類**，例如：

```powershell
python scripts/review_queue.py --target "C:\Projects\MyApp" --categories AC --recover-integrity
```

內部程式可透過 `partial_evidence_integrity.recover(target_root, "AC")` 呼叫相同守門。已成功提交且沒有 pending 時，會驗證 Journal／Manifest 並回報 `recovered=false`、`already_completed=true`；重複執行不重複新增 Journal、Finding 或歷史紀錄。

復原前會完成下列核對：

- 分類 Manifest、既有 Journal SHA256 鏈、連續交易序號、預寫交易的前一版指紋及 staged SHA256 全部一致；禁止跨分類、路徑跳脫及額外 Journal。
- Git Revision、原始碼雜湊、分類來源快照未異動；原始／目標檔案 SHA256 必須逐一符合。只允許交易中列出的新增修訂歷史，所有其他非預期新增／刪除／第三種內容均拒絕。
- 若 Journal 已寫入而 Manifest 尚未更新，核對新 Journal 的精確內容後補完提交；若 Manifest 已更新但 staged／pending 尚未清除，只能在所有受控檔案均為**已提交版本**時清理。
- 上述核對全部通過後才補寫尚未完成的檔案，確認提交 Journal 與 Manifest，最後清理暫存。復原中再次中斷時仍保留 pending，稍後必須再次明確執行復原。

**限制：** `--recover-integrity` 不進行語意重審或自動修復來源異動，不能推論第三種內容是否安全。無法確認時保留現場供人工核對，絕不強制重設 Finding。多檔案提交並非作業系統級原子交易；斷電或強制終止後的完整性仍需核對。
