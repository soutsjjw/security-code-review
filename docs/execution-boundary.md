# B0、P4-A 與 P0 安全邊界（實驗性）

本功能目前採 **L3 事後稽核**，不代表已取得可信的執行器全入口清單、L1/L2 隔離或自動化人工覆核。一般審查預設走 legacy 模式，以保留既有中途狀態、Manifest、Journal 及 Findings。

## 啟用條件

先執行原有 Python 環境檢查及 `review_log.py start`，再執行：

```bash
python <SKILL_ROOT>/scripts/execution_boundary.py --target <TARGET_ROOT> --begin
python <SKILL_ROOT>/scripts/execution_boundary.py --target <TARGET_ROOT> --inspect --batch-id preflight
```

必須在實際 Agent 的執行環境明確設定 `SECURITY_CODE_REVIEW_EXECUTION_MODE=optimized`，正式 Stage／Integrate 才執行 L3 邊界比對及拒絕違規批次；未執行 begin 時會拒絕交易，不能默默將未建立的稽核基準當作合格。

- `scripts/execution_boundary.py`：記錄執行能力評估及 `analysis/` 腳本清單的 SHA256，監測新增／異動，不自行清除舊腳本。
- `scripts/execution_boundary_events.py`：根據 `schemas/execution-boundary-event-v1.schema.json` 建立逐 Batch 追加式事件，驗證鏈與不可變 Run 摘要。預設沒有可信覆核者通道，`block` 事件不能由 Agent 自行宣稱已推翻。
- `scripts/legacy_script_archive.py --target <TARGET_ROOT> --plan`：不修改審查狀態，只建立舊腳本盤點；`--archive` 只複製及 Journal 追加封存憑證，不執行或刪除舊腳本。依賴不明時 `allow_cleanup=false`。
- `scripts/b0_baseline.py`：只記錄有來源的耗時、工具呼叫及明確回報的 Token；詳見 [B0 基準](b0-baseline.md)。

## 安全限制

L3 可以辨識 `analysis/` 的 `.py`、`.sh`、`.js` 等已存在或新增執行檔變更，但不能可靠觀察 `python -c`、heredoc、已刪除的暫存檔、執行器新增工具入口或所有動態程序。不可將「未偵測到」稱作「保證沒有」。既有腳本只能保持並監測，不能宣稱已強制禁止其執行。

邊界違規時只隔離本次批次，正式資料不被改寫，其他獨立工作可繼續；沒有可信覆核通道時，阻擋事件保留 `pending_review`。不可以無效的 Stage／Integrate 重試、假造證據或 Agent 自行覆核解除阻擋。

Journal 新交易可附加 `boundary_attestation` 與 `archive_attestation`；歷史 v1 日誌的受控檔案集合不變。SHA256 雜湊鏈本身沒有加密簽章，不能抵禦有權改寫全部檔案的攻擊者。

## 現階段尚未完成的能力

尚未完成可信人工覆核通道、完整執行器能力清單認證、跨代理獨立證據複核、增量影響閉包與完整 E2E 大型審查驗收。因此此實驗性模式不可被宣稱已達到 v3.2 全部目標；正式進入第二輪仍必須經既有全量守門。
