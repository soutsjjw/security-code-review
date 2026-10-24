# 分類證據完整性：R1 基礎契約

此階段僅新增 `scripts/partial_evidence_integrity.py`，**未接入**分類 `stage/integrate`、第二輪開始流程或報告驗證；因此不能宣稱已解決分類證據整合中斷問題。R2 將接入受控提交，R3 才新增交易復原介面。

## 目標與隔離範圍

AC、AU 等分類各自擁有：

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
    ├── integrity-pending.json             # R2/R3 將使用；R1 發現即拒絕
    ├── integrity-journal/00000000.json   # R1 初始封存
    └── integrity.lock                   # 取得分類排他鎖時短暫存在
```

- `source-snapshot.json` 固定當前來源 Git Revision／SHA256，及其在分類 assessment 的指紋。索引 `partial/_shared/analysis/` 為共用**候選分析**，沿用現有索引完整性校驗，不混入分類證據交易。
- 所有受控檔案使用**原始 bytes** 計算 SHA256；不存在的固定證據檔以 `null` 記錄。第二輪修訂歷史為動態清單，新增、刪除或內容變動皆會被發現。
- Manifest 記錄分類、格式版本、交易序號、來源指紋及最新 Journal head；第 0 筆 Journal 記錄初始檔案雜湊，後續交易須形成連續雜湊鏈。
- 交易鎖由排他建立保護；偵測到已存在鎖應**拒絕**，不自動刪除可能仍由其他代理持有的鎖。
- 第三種內容、來源異動、Journal 篡改、未知修訂歷史、未完成交易／staged 批次皆不得由初始封存清除或自動信任。
- 既有 Finding、已完成規則、逐檔證據或第二輪資料需先核對來源和安全結論後，才能**明確**執行 `initialize(..., explicit=True)`；不允許為修復錯誤而重新初始化已封存內容。
- 不變更既有完整 70 項 `evidence_integrity.py`、正式報告或規則判定。

## R1 API（程式內部，不是使用者 CLI）

```python
from partial_evidence_integrity import initialize, errors, locked

initialize(target_root, "AC")                   # 僅初始乾淨狀態
initialize(target_root, "AC", explicit=True)    # 既有審查已經人工核對
issues = errors(target_root, "AC")             # 唯讀完整性核對
with locked(target_root, "AC"):                # 分類排他鎖
    pass
```

注意：目前 `review_queue.py --categories AC --integrate` **尚未呼叫 R1 完整性交易**。在 R2 接入前使用以上 API 建立封存，之後使用舊整合程序更新證據會導致 SHA256 不一致；此為預期的 fail-closed 現象，非可交付的完整分類交易功能。請勿手動刪除 Manifest、Journal、鎖或 Finding 以規避驗證。

## R2／R3 接線要求

R2 應在同一分類排他鎖內完成輸入／來源與舊版雜湊核對、寫入完整 pending 的 ahead-log，並以完整性鏈提交 `assessment`、四種安全證據、第二輪固定基準與修訂歷史。R3 提供明確復原指令及原／新 SHA256 限制，只在確認無第三種內容時補完交易。完整模式仍使用既有交易器，避免兩套有不同的安全語意。
