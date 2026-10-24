# 審查證據完整性、交易日誌與安全復原

此功能使用 SHA256 將來源快照、正式 `assessment.json`、第一輪／第二輪判定基準及工作中驗證 JSON 固定成**可檢查的資料完整性鏈**。不新增安全規則、不修改正式報告 Schema、不代替單一主代理的真實程式碼審查。

## 啟用及資料遷移

在受測專案執行 `analysis_prepare.py` 建立新版索引後，新審查的 `review_queue.py --init` 會為第一份空白評估自動建立 `analysis/integrity-manifest.json` 及第 0 筆 `analysis/integrity-journal/00000000.json`。既有已保存的審查資料**不能自動視為可信來源**；必須先核對 assessment、Finding、相關工作中資料、來源快照，再明確執行：

```bash
python "<SKILL_ROOT>/scripts/review_safety.py" --target "<TARGET_ROOT>" --seal-integrity
```

已存在不一致的鏈、未整合批次或正在復原的交易不得重新封存。舊索引資料不強制追溯套用新的完整性契約；以新版索引開始審查時必須遵守本流程。

## 受控資料與正常整合

受控檔案包含 `assessment.json`、`analysis/review-snapshot.json`、`rule-closures.json`、`control-verifications.json`、`decision-audits.json`、`adversarial-reviews.json`、`recheck-required.json` 及 `first-pass-baseline.json`。每筆交易日誌記錄來源快照指紋、所有受控檔案的 SHA256、前一筆日誌的雜湊及暫存檔的 SHA256；資料內容更新只能透過已授權的整合操作。驗證器會拒絕來源、JSON、日誌或 manifest 的版本失配。

```bash
python "<SKILL_ROOT>/scripts/review_safety.py" --target "<TARGET_ROOT>" --stage "<批次.json>"
python "<SKILL_ROOT>/scripts/review_safety.py" --target "<TARGET_ROOT>" --integrate
python "<SKILL_ROOT>/scripts/review_safety.py" --target "<TARGET_ROOT>" --validate
```

`--stage` 同時綁定目前交易 head；若其它整合已先完成，舊批次不得直接覆寫，需重新讀取目前資料、核對衝突後重新暫存。不能直接修改已封存 JSON；應透過批次修訂工作流程。既有 Finding 不得因改判而刪除或覆寫。

## 寫入途中中斷

整合前先建立 `analysis/integrity-pending.json`，保留預期的更新資料、各檔寫入前與寫入後 SHA256 及暫存指紋。若多檔寫入中途斷電，後續 `--integrate`、`--stage`、`--validate` 將停止，**不會自行忽略不一致**。核對原因後，透過：

```bash
python "<SKILL_ROOT>/scripts/review_safety.py" --target "<TARGET_ROOT>" --recover-integrity
```

復原只接受受控檔案等於原版本或預期新版本；若存在第三種內容、交易鏈或暫存被修改，復原會拒絕，須人工核查。中途已寫入 manifest 而尚未刪除 pending 的情況也可依同一程序收尾。復原後請重新執行 `--validate` 及佇列核對。

## 來源變更與第二輪複核

`--snapshot-refresh` 會以新交易記錄來源快照更新、清除舊控制鏈結案並建立全部已完成規則的重新查核義務。執行 `analysis_prepare.py` 重建結構索引與來源盤點後仍要實際重新審查；**刷新雜湊不等於重新 Pass**。`--begin-second-pass` 的第一輪基準也會寫入完整性日誌；`--restart-second-pass` 仍依原流程歸檔第一輪與第二輪歷史，再以交易更新基準／重置第二輪紀錄。既有弱點與裁決不會由完整性工具直接刪除。

## 安全邊界

本機 SHA256 日誌屬**意外修改與未經流程更新偵測**，而非帶金鑰的數位簽章。對所有資料與日誌均有寫入權的人，仍可能重新計算整份鏈；若需防止惡意竄改，應另將最後一筆日誌雜湊保存至外部不可變稽核系統。完整性鏈不能自動判斷安全程式碼或確認 AI 真正閱讀來源，也不能聲稱達成獨立稽核。受測專案原始碼不由此機制修改。
