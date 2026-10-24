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

## 中斷處理與限制

若寫入期間中斷，保留 `integrity-pending.json`、`staged/pending.json` 及已寫入的檔案，**不會自動重播或回滾**。再次執行 stage／integrate 會因未完成交易拒絕操作；不得直接刪除 Manifest、Journal、Pending 或 Finding 來解除阻擋。

後續將提供明確的中斷復原入口，在核對所有受控檔案只能符合原 SHA256／目標 SHA256、沒有第三種內容、來源快照不變後，才能補完原交易。強制終止、斷電或作業系統尚未落盤的資料，仍須依檔案完整性與交易日誌調查，不宣稱多檔案 OS 級原子提交。
