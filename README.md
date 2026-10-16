# Company Security Code Review — v2.0.0-rc1

**定位：** 跨系統共用 70 項原始碼資安審查基準；無 EDS 或其他特定專案掃描結論。
**狀態：** `candidate_pending_company_security_approval`。技術規則已標準化，但公司正式規範尚需資安／法遵簽核。

## 包含內容
- `rules.yaml`、`rules.json` 與 `rules/*.yaml`：70 項共用規則，每項有適用／判定／檢查／證據／例外／風險／文獻欄位。
- `docs/70-rules-standardized.md`：70 項逐條定義，完整可人工審閱。
- `docs/traceability.csv`：與 ASVS 5.0.0 已核對需求號、OWASP 2025 建議風險類別、臺灣參考指引對照狀態。
- `standards/standards-register.yaml`：標準版本、權威網址與施行注意。
- `policies/applicability-matrix.yaml`：獨立分級與適用性原則。
- `profiles/project-profile.example.yaml`：不同專案自己的配置。
- `schemas/*`：規則及審查結果 JSON Schema。
- `scripts/*`：一致性及證據驗證程式。
- `examples/assessment.example.json`：70 項全部 Review 的**格式範例**，不是實際審查報告。

## 驗證
```bash
python scripts/validate_package.py
python scripts/validate_assessment.py examples/assessment.example.json
```

## 如何用於新系統
1. 將本套件放入 `.agents/skills/security-code-review/` 或 Agent 支援的 Skill 位置。
2. 建立系統專屬 `project-profile.yaml` 並由負責人確認。
3. 輸入：`依 security-code-review Skill 對目前專案執行 70 項資安審查，輸出 assessment.json。`
4. 驗證所有規則的 evidence、狀態與來源版本，再產生 HTML 報告。

## 注意
- 70 項不是完整 OWASP ASVS，不能自稱已完整通過 ASVS 等級驗證。
- 已對應的 ASVS 條號是**相關技術要求**，並非 70 項與 ASVS 一對一、完全等價。
- Web 安全參考指引 v3.2 的具體條款，未取得原始附件逐條比對前仍標記 `pending`。
- 臺灣個人資料保護法 2025-11-11 的部分修正條文施行日未定，需採實際施行條文進行判斷。
