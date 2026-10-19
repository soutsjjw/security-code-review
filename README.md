# Security Code Review Skill v2.1.6

公司跨系統共用的 **70 項資安原始碼審查 Skill**。在被審查專案呼叫一次，Agent 執行檢核並產生可離線開啟的 HTML／JSON 報告。規則集 `2.0.0-rc1` 尚待公司資安核定。

## 快速使用

1. 安裝本 Skill（見下節），重新開啟 Codex／Claude Code 工作階段。
2. **開啟欲檢查的專案目錄**，在 Codex 對話輸入：

   ```text
   $security-code-review
   ```

   或指定另一個專案：

   ```text
   $security-code-review /path/to/project
   ```

   也可以指定檢核範圍，如 `$security-code-review src/Api`。Claude Code 改用 `/security-code-review`。**這是 Agent 的聊天指令，不是 PowerShell／Bash 的系統命令。**
3. Agent 自動盤點專案、**逐項完成 70 項實際檢核**，將 `assessment.json` 和專案資訊寫在受測專案內，再呼叫 Python 產生與驗證報告。

**報告一律輸出至受測專案，不會寫入安裝的 Skill 資料夾：**

```text
你的專案/
└── reports/security-code-review/
    ├── assessment.json
    ├── project.json
    ├── presentation.json      # 有佐證時才產生
    ├── report.json
    └── CodeReview_YYYYMMDD.html
```

已查核但缺少外部環境、部署與人工佐證的控制項可標 `review`，不可將尚未執行者填為 `review`。每項須附 `execution`（`state`、`methods`、`summary`、可選 `inspected_paths`）；正式報告僅接受全部 `completed`。

## 安裝（只需一次）

**Codex 全域共用**：將整個 `security-code-review/` 資料夾放到 `~/.agents/skills/security-code-review/`（Windows：`%USERPROFILE%\.agents\skills\security-code-review\`）。

**Codex 單一專案**：放到 `<專案>/.agents/skills/security-code-review/`。

**Claude Code**：使用 `~/.claude/skills/security-code-review/`，或專案的 `.claude/skills/security-code-review/`。

例如在 macOS／Linux／WSL 解壓下載的 ZIP 後：

```bash
mkdir -p "$HOME/.agents/skills"
cp -R security-code-review "$HOME/.agents/skills/security-code-review"
```

Windows PowerShell：

```powershell
New-Item -ItemType Directory -Force "$env:USERPROFILE\.agents\skills" | Out-Null
Copy-Item -Recurse -Force .\security-code-review "$env:USERPROFILE\.agents\skills\security-code-review"
```

從私有 GitHub 安裝時，可在已設定 SSH 權限的環境中將 `develop` 分支直接 Clone 到上述目錄。**需確認目標 `develop` 分支包含最新版套件**，否則遠端不會包含最新版功能。

## TACERT V2：網站安全管理指南

已整合 **臺灣學術網路危機處理中心（TACERT）《網站安全管理指南》2022-08 修訂 V2**：在原有 70 項規則上，補充 39 個可追溯檢核焦點（第二章 12 項常見缺失、第四章 14 項安全檢測、第五章 13 類防護措施）。

- 對照清單：`standards/tacert-v2-checklist.yaml`（TACERT 項目 ID、來源 PDF 頁碼、檢查方法、預期證據及既有規則 ID）。
- 自動佇列：`review_queue.py` 在對應的 `next_checks[].tacert_v2_checks` 提供審查提示；AI 實際查核後將 TACERT ID、完成的靜態分析及需補證據事項寫入原有規則的審查理由與摘要，不更動 70 項規則進度模型。
- **無法以原始碼判定的防毒、主機防火牆、RDP、Port 掃描、事件檢視器、檔案異動、DDoS、還原演練及滲透測試，須列為待確認**；不得以未發現程式碼證據判定安全，也不能宣稱已做動態測試。
- 文件中的 OWASP Top 10 採 **2021** 版，與本 Skill 的 **OWASP Top 10 2025** 風險分類分別引用。
- 本次採補充檢核，不虛增成 109 條獨立規則；後續若需新增正式規則，須同步更新規則集、Schema、報告驗證與測試。

## OWASP Top 10:2025 正式風險分類對照

官方依據：[OWASP Top 10:2025](https://top10.owasp.org/2025/)；十類風險以 `standards/owasp-top10-2025.yaml` 維護版本化來源、審查方向、相關規則與**未完整涵蓋項目**。

- **現有 70 項規則保留**；2025 的 A01～A10 為風險分類，不虛增成 80 條獨立規則、也不是直接的法遵條文。
- `review_queue.py` 透過 `next_checks[].owasp_2025_categories` 提供各類別的實際檢查方向，Agent 應在對應規則的 `decision_reason` 和 `execution.summary` 記錄查核與缺證據情況。
- `generate_report.py` 將對照寫入 `report.json` 的 `rules[].owasp_2025_categories`，HTML 另顯示「OWASP Top 10:2025 風險分類對照」、關聯檢核結果及仍需確認的範圍；**相關規則通過不代表整個風險類別已完全符合**。
- 2025 重要差異：**A03 軟體供應鏈失效**（不僅是過時元件）、**A09 安全日誌與告警**、**A10 異常條件處理不當**；**SSRF 屬 A01:2025**，不再是 2021 的 A10。
- TACERT 2022 年的 V2 PDF 仍保留其 **OWASP Top 10:2021** 原始引用；2025 依據是另外新增的官方版本，**不改寫歷史文件**。
- 如果先前的 `assessment.json` 已標記完成，不能因新的 2025 對照自動宣稱重新審查；應核對當時實際查核證據並重新執行未涵蓋的安全查核。

## 資通系統防護基準驗證實務 V1.3（第二層：80 項控制措施）

正式依據：《資通系統防護基準驗證實務》V1.3（國家資通安全研究院，115/06/03），對照《資通安全責任等級分級辦法》第 11 條及附表九、十。清冊：`standards/tw-system-baseline-v1.3.yaml`。

- 保留**原 70 項程式碼規則**及 TACERT/OWASP 對照；另建立 **80 項獨立系統防護基準**，不是 70+80 個程式碼檢核或額外 80 個已執行檢測。
- 文件第 2 章七構面、27 類控制措施分級：**普 45 項、中 62 項、高 80 項**。僅以受測系統的 `project.protection_demand_level`（普／中／高／待確認）決定適用項目，不以機關資安責任 A～E 或弱點數量換算。
- Agent 的原有審查佇列 `next_checks[].system_baseline_v13_controls` 提供關聯控制、原文條次、適用級別、原始碼可檢視部分及應備佐證；**不是獨立符合性結果**。
- 完整報告 `report.json` 新增 `system_baseline`（80 筆、適用等級、各項狀態、條次、原規則關聯、佐證資訊），HTML 增加「資通系統防護基準 V1.3（獨立驗證）」。
- **預設全部未獨立驗證**（沒有分級為 `pending_level`，有分級但無足夠證據為 `not_assessed`，不屬該分級者為 `not_applicable_by_level`）。原 70 項 `pass` 絕不自動推出基準 `pass`。
- 有正式分級佐證時，可在受測專案的 `reports/security-code-review/project.json` 加入：
  ```json
  {
    "name": "受測系統",
    "protection_demand_level": "中",
    "protection_demand_level_basis": "範例：系統防護需求分級之核定紀錄或可核對依據"
  }
  ```
  若無依據，請保留「待確認」；不影響原 70 項審查。
- 有實際人工／外部佐證後，可選擇建立 `reports/security-code-review/baseline_assessment.json`，完整評估資訊由 `complete_review.py` 自動帶入報告，**不改動既有 assessment.json**：
  ```json
  {
    "controls": [
      {
        "id": "TW-SB-2.1.3.2",
        "status": "pass",
        "reason": "已核對伺服器端授權呼叫鏈及實際功能測試",
        "reviewer": "資安審核者",
        "verified_on": "2026-10-20",
        "evidence": ["授權測試紀錄 ART-01、程式碼路徑與行號"]
      }
    ]
  }
  ```
  上例**僅為格式示範，不是真實審查結果**。狀態可為 `pass/fail/review/na`；pass/fail 需有非空證據參照、審核者、日期及理由，否則拒絕報告驗證。**不得將 AI 自行推斷、掃描佇列已列出或不存在之測試填作佐證**。
- 檔案來源 PDF **不含完整附件一檢核表**；本次只引用正文 80 項和條次，不聲稱已取得附件完整內容。

單一指令仍是 `$security-code-review`，輸出的原始碼審查依然以 70/70 完成為前提。**80 項符合性屬獨立驗證**，缺部署／制度／動態測試記錄時不得宣稱已通過全部基準。

## Codex `/goal` 完整審查指令

若所使用的 Codex 版本支援 `/goal`，可在**受測專案的 Codex 對話**中輸入以下完整指令（不是 PowerShell／Bash 指令）。目標是完成全部 70 項審查後才交付報告；是否能於單次執行內完成，仍取決於 Codex 的執行環境與資源限制。

```text
/goal 使用 $security-code-review Skill，完整執行目前專案的全部 70 項資安檢核。

完成條件：
1. 逐項實際審查全部 70 條規則，確認 execution.state 均為 completed。
2. 載入既有 assessment.json，保留所有已發現弱點及證據。
3. 發現弱點時寫入 Finding，不修改原始碼、不要求先修復。
4. 缺少部署、政策或動態測試證據時，記錄已完成的靜態分析及待確認事項，繼續其他檢核。
5. 每批保存結果，自動繼續下一批，直到 70/70。
6. 執行 complete_review.py，成功產生並驗證 HTML 與 JSON 報告。
7. 只有在真正無法繼續的執行錯誤或資源限制時才停止，並保留進度及說明原因。

在完成以上條件前，不得將部分檢核結果視為最終交付。
```

此指令不會取代逐項查核，也不能將尚未執行的項目標為 `completed`。若環境不支援 `/goal`，仍可執行 `$security-code-review`，由 Agent 依下述佇列迴圈進行檢核。

## 70 項審查的實際執行迴圈

單次 `$security-code-review` 由 Codex 自動進行下列工作：

1. 呼叫 `scripts/review_queue.py --target <TARGET_ROOT> --init --batch-size 10`。若既有 `assessment.json`，保留所有 Finding 與查核結果。
2. 依工具列出的待辦規則實際讀取受測程式、追蹤呼叫鏈、驗證證據；發現弱點就寫入 Finding，**不要先修補**。
3. 每批完成就儲存 `assessment.json`、再次取得下一批，直到 `ready_for_report=true`（70 項皆已審查）。缺外部證據時採已查核的 `review`，不得直接跳過，也不得因此結束工作。
4. 由 Agent 執行 `complete_review.py`，自動產生並驗證報告後交付 HTML／JSON 路徑。

排程工具只提供待檢核佇列與進度統計，**不是會自動判斷漏洞的靜態掃描器**；70 項實質查核仍須由 Codex 完成。若遇到真實阻斷錯誤才停止，並說明原因。

## 混合來源編碼及完整檢核

來源程式碼可為 UTF-8、UTF-8-BOM、帶 BOM 的 UTF-16；遇到舊式編碼時預設依序嘗試 CP950、CP1252，**自動唯讀回退，不需再次取得使用者確認**；報告驗證會保留警告（此回退不代表百分之百辨識正確）。可在 Agent 內部呼叫時指定 `--source-encodings cp950,cp1252`，絕不修改受測程式碼。JSON／HTML 輸出仍統一 UTF-8。

`status=review` 代表「已執行審查但仍待外部證據」，不是尚未檢核。未完成或阻斷的項目需保留 `execution.state=pending/blocked`，並使正式報告驗證失敗；逐項完成後再產生 HTML。腳本只驗證審查資料，不會取代 Codex 的程式碼分析。

審查過程如發現漏洞，應將其列入 Finding、建議修補與風險排序，繼續完成其餘檢核，**不修改受測原始碼，也不要求先修復再產報告**。若大型專案需要分批查核，應保存 `assessment.json` 進度，繼續未完成項目。

遇到 Codex 不能以 UTF-8 讀取來源時，Agent 可自動使用下列工具讀取指定行號（使用者通常不需手動執行）：

```powershell
python "$env:USERPROFILE\.agents\skills\security-code-review\scripts\source_reader.py" --source-root . --path "src/Infrastructure/Identity/IdentityService.cs" --start 550 --end 600
```

## 報告安全等級（審查時自動初判法定 A～E 級）

「基本資訊與摘要」的**資通安全責任等級（A～E）**係指機關等級，依《資通安全責任等級分級辦法》（民國 115 年 1 月 7 日修正）第 2 至 10 條分級，A 至 E 由高至低；同時符合多個等級依第 9 條採最高等級，實際核定程序仍由權責單位辦理。

**無需在執行 Skill 前先提供分級。** Agent 隨 70 項審查自動比對已查核的程式碼、設定、權限控管與業務文件，能提出具體線索時於報告顯示「初步研判」與佐證，無法判斷時顯示「待確認」及原因，不中斷 70 項檢核。若 Agent 未產生初判，`generate_report.py` 會從完成審查的 `execution.inspected_paths` 自動搜尋明確角色／權限管理程式碼，作為第 6 條 C 級**技術條件線索**；無線索則記錄尚缺的機關業務、維運與核定資訊。此結果不能證明法定核定、不能排除較高的 A／B 級，亦不能以無線索推定 D／E 級。

`project.security_level_assessment` 會儲存自動初判（`status`、`level`、`basis`、已審查證據路徑與行號、`missing_information`），並在 HTML「安全等級判斷說明」呈現。只有**已核定的等級**才設定 `security_level`。

`reports/security-code-review/project.json` 的 `security_level` 僅接受 `A`、`B`、`C`、`D`、`E`、`待確認`、`不適用`。未有權責單位確認資料時填「待確認」或省略；法規非適用對象可標示「不適用」。指定 A～E 級時，必須填入 `security_level_basis` 記錄可核對的認定／核定依據，不得由 AI、程式碼或弱點數量推定。

```json
{
  "name": "受測系統",
  "security_level": "B",
  "security_level_basis": "示例：權責單位核定日期、文號或其他可核對資訊"
}
```

未取得核定資訊時可省略 `security_level` 或填「待確認」，系統會自動產生初判或待確認說明。此法定分級與「整體風險評估」及資通系統防護需求分級（第 11 條、附表九）**不同**。

法規來源：https://law.moj.gov.tw/LawClass/LawAll.aspx?pcode=A0030304

## 報告審查範圍與檔案數

`assessment.scope` 是文字範圍，不是掃描檔案數。報告在「基本資訊與摘要」增加專案數、**有逐檔紀錄的實際審查檔案數**、盤點檔案數、排除檔案數與檔案類型；「審查檔案明細」顯示專案、排除原因與檔案清單及其 70 項規則的關聯。

在 `assessment.json` 原有七項必要欄位之外，Agent 可記錄：

```json
"scope_details": {
  "projects": [
    {"name": "WebAPI", "path": "src/WebAPI"},
    {"name": "Core", "path": "src/Core"}
  ],
  "excluded_paths": [
    {"path": "src/Legacy", "reason": "不在本次審查範圍"}
  ]
}
```

單一專案可使用 `{"name":"系統名稱","path":"."}`。每項實際檢查的檔案路徑必須寫入對應 `execution.inspected_paths`；盤點到檔案不等於完成審查。統計由 Python 根據**報告產生時的工作目錄**自動計算，不手動輸入檔案／專案數。未提供專案對照時，報告會顯示「未提供」，不假設只有一個專案。統計與 Git Revision 可能不完全一致，應確認版本。

## Python 是否必要？

- Skill **辨識及 AI 閱讀程式碼不需要** Python。
- **目前的 HTML 產生、JSON／HTML 驗證需要 Python 3.10+** 與 `requirements.txt` 依賴。只需安裝一次，不用每次手動執行三個程式。

Codex 全域安裝範例（從任意目錄安裝依賴）：

```bash
python -m pip install -r "$HOME/.agents/skills/security-code-review/requirements.txt"
```

PowerShell：

```powershell
py -3 -m pip install -r "$env:USERPROFILE\.agents\skills\security-code-review\requirements.txt"
```

如公司限制全域安裝，請由系統管理者採公司核准的虛擬環境。依賴為 `jsonschema`、`referencing`、`PyYAML`。

## 為何從受測專案執行，而不是 Skill 目錄？

- **Skill 目錄只負責規則與工具**；Agent 讀取其中的 `SKILL.md`、規則、Schema 與 Python 程式。
- **受測專案是工作目錄**；原始碼搜尋、Git Revision、路徑與行號、報告輸出都相對受測專案。
- `complete_review.py` 只是 Agent 最後呼叫的整合流程，**不會單獨掃描原始碼**；`assessment.json` 必須先由 Agent 真正審查後建立。

在受測專案根目錄執行時，Agent 內部呼叫的指令概念如下（使用者通常不需要操作）：

```bash
python <SKILL_ROOT>/scripts/complete_review.py --target .
```

本程式會自動執行 `validate_assessment.py`、`generate_report.py`、`validate_report.py`，從受測專案的 `assessment_date` 決定 HTML 檔名，並開啟來源檔嚴格核對。

## 維護人員測試

在 Skill 根目錄執行（只供維護者驗收，不是一般使用流程）：

```bash
python scripts/validate_package.py
python -m unittest discover -s tests -v
```

主要檔案：`SKILL.md`、`rules/`、`schemas/`、`templates/security-report.html`、`scripts/complete_review.py`、`scripts/generate_report.py` 與 `scripts/validate_report.py`。

> 注意：檢核格式與來源檔案驗證通過，不等於資安問題已經過動態測試，亦不代表已取得法遵或公司資安簽核。
