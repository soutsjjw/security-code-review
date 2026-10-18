---
name: security-code-review
version: 2.1.1-rc1
description: 公司共用之 70 項跨系統原始碼資安檢核，依規範及專案適用條件執行審查，產生證據化 JSON 與 EDS 風格 HTML 報告。
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


## HTML 報告產生與驗證（v2.1 整合）
1. Skill 目錄與被審查系統可能不同；找出本 `SKILL.md` 所在的絕對路徑作為 `SKILL_ROOT`，並由該位置解析 `rules.json`、`schemas/`、`scripts/`、`templates/`。
2. 完成檢核後先將 70 項審查結果寫入受測專案的 `reports/assessment.json`，包含真實 Git Revision 及證據，執行 `python <SKILL_ROOT>/scripts/validate_assessment.py reports/assessment.json`。
3. 建立 `reports/project.json`（系統顯示資訊）與可選 `reports/presentation.json`；不得沿用任何舊系統缺失與數字，也不可捏造修正期限、Before / After 或安全優點。
4. 從受測專案根目錄執行：`python <SKILL_ROOT>/scripts/generate_report.py --assessment reports/assessment.json --project reports/project.json --source-root . --strict-sources --save-report reports/report.json --output reports/CodeReview_YYYYMMDD.html`。若有 `presentation.json`，加上 `--presentation reports/presentation.json`。
5. 驗證：`python <SKILL_ROOT>/scripts/validate_report.py --report reports/report.json --html reports/CodeReview_YYYYMMDD.html --source-root . --strict-sources`。
6. 只有程式結束狀態為 0，才可說「報告結構與來源驗證通過」；不能稱漏洞已被動態驗證或已通過公司資安認證。
7. 產生及驗證報告的現行腳本**需要 Python 3.10+** 與 `requirements.txt`；純 Skill 指令的讀取則不需要 Python。
