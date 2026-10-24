# 分類證據交易與復原驗收

## 驗收範圍

分類交易的 `stage → integrate → --recover-integrity` 必須在寫入中斷、證據篡改或來源版本變化時保持可驗證的狀態，不得消失 Finding、跨分類覆寫或錯誤宣稱檢核完成。

| 驗證項目 | 測試方式 | 完成條件 |
|---|---|---|
| 每個寫入邊界 | 中斷證據、assessment、Journal、Manifest、staged／pending 清理 | 完整性驗證與報告交付先拒絕；CLI 核對後只補完該筆交易 |
| 硬碟已滿／預寫失敗 | 拒絕寫入 `integrity-pending.json` | 不修改既有受控證據，保留 staged 供重新整合 |
| 重複復原 | 對已完成交易再次呼叫 `--recover-integrity` | Journal、Manifest、Finding 與已保存證據保持逐位元相同 |
| 不可信狀態 | 修改來源、staged、Journal、pending 或受控證據 | 拒絕自動復原，保留現場，不產生通過報告 |
| AC／AU 隔離 | 故意中斷 AC，同時保留 AU 已完成交易 | AU Journal、Manifest、Finding 不改變 |
| 正式模式隔離 | 保留原完整審查 HTML、JSON | 分類整合／復原不改變正式輸出 |
| 跨檔測試 | 建立 Controller、Service、Repository、DI 與跨專案參照之 .NET 8 檔案 | 共用候選索引可識別實際關聯，僅供證據定位，不宣稱控制 Pass |
| 跨平台 | Linux 全套單元測試及 Windows 全套單元測試 | 兩者均成功，Windows 以實際 .NET 8 SDK 編譯測試夾具 |

## CI 與手動執行

既有 CI 在 Linux 執行全套測試及規則品質驗證；`.github/workflows/category-transaction-acceptance.yml` 加入 Windows Python 3.13 + .NET 8 SDK 的**全套**單元測試，以覆蓋 Windows 原生 subprocess 解碼與平台相容性。

在專案根目錄執行：

```powershell
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python scripts/validate_package.py
```

只重跑故障復原整合驗收：

```powershell
python -m unittest discover -s tests -p "test_category_transaction_acceptance.py" -v
python -m unittest discover -s tests -p "test_partial_integrity_recovery.py" -v
```

**判定限制：** 此驗收使用實際可讀的 .NET 8 多專案來源、確定性的故障注入與真實 CLI 呼叫，但規則 `Pass／Fail／Review` 判定沒有由 Agent 完成逐條實際攻擊面審查，因此不能將本次交易測試、構建成功或範例檔案視為外部真實專案的資安審查驗收。真實專案的完整端對端 Agent 審查應作獨立驗收。
