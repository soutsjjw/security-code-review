---
name: security-code-review
version: 2.0.0-rc1
description: 公司共用之 70 項跨系統原始碼資安檢核，依規範及專案適用條件執行審查並輸出證據化 JSON。
---

# Security Code Review — 70 項跨系統共用標準

> 發布狀態：rc1／待公司資安核定；不能聲稱已獲法遵認證。

## 執行規則
1. 載入 `standards/standards-register.yaml` 與 `policies/applicability-matrix.yaml`；不得自行推定法規適用性或級別。
2. 為本次專案建立專屬 `project-profile.yaml`，用 `profiles/project-profile.example.yaml` 為範本。
3. 讀取 `rules/{AC,AU,IN,CR,EH,LG,DP,PD,BC,SI}.yaml` 共 70 項，不允許跳過、增加或重編 ID。
4. 逐項辨識系統功能與控制責任，確認來源碼／部署／外部 IdP 等証據是否可取得。
5. 對適用項目執行唯讀原始碼審查、跨層資料流或授權鏈追蹤。只有在授權的安全測試環境下執行非破壞性測試；不得擅自滲透正式系統。
6. 對每項記錄 Pass、Fail、Review 或 N/A，並附具體適用理由、判定理由與證據。
7. 風險與檢核狀態分開計算。對 Fail 先排除外部替代控制與重複發現，再形成 Finding。
8. 原始碼取證填相對路徑、真實行號及 Git Revision；隱去個資、密碼、金鑰與 Token。
9. 依 `schemas/assessment.schema.json` 產生 `assessment.json`，執行 `scripts/validate_assessment.py`。
10. 報告 HTML 只能從本次 `assessment.json` 渲染，不可複製歷史系統檢核數字或缺失。

## 強制限制
- 未提供環境／人工作業證據的控制應 Review；不能因原始碼沒有相應設定就 Fail。
- 缺少必要證據不可判 Pass；N/A 需明確說明功能與適用義務。
- 不得把 OWASP Top 10 當成直接的法規符合性條文。
- 例外／風險接受需有正式批准；不會將 Fail 改為 Pass。
- 不可修改被審查系統原始碼。

## 工具命令
`python scripts/validate_package.py`
`python scripts/validate_assessment.py path/to/assessment.json`

## 文檔
- `docs/70-rules-standardized.md`：70 項逐條正式化草案
- `docs/standardization-policy.md`：規範優先序、來源與分級
- `docs/applicability-and-exceptions.md`：適用、例外及判定
- `docs/approval-checklist.md`：公司正式發布前必要簽核
