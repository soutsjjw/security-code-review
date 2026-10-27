# 逐檔來源與規則關聯契約

每個應審查原始碼或設定檔都必須由審查 Agent 實際閱讀，於 `assessment.file_reviews[]` 登錄一筆紀錄。路徑相對受測根目錄，不接受絕對路徑、越界或排除目錄。

```json
{
  "path": "src/Auth/Session.cs",
  "sha256": "必須填入該檔案標準內容（移除 UTF-8 BOM、CRLF 視為 LF）的 64 字元小寫 SHA256；可用 source_reader.py --digest 取得",
  "summary": "實際追蹤 Session 授權管線與使用權杖的呼叫；已檢查使用者身份與存取限制。",
  "methods": ["唯讀原始碼檢閱", "資料流及呼叫鏈追蹤"],
  "category_screening": {
    "AC": {"rule_ids": ["AC-01"], "reason": "實際分析 Session 生命週期，AC-01 直接適用；其他 AC 規則未在此檔實作。"},
    "AU": {"rule_ids": [], "reason": "此檔案未實作登入稽核紀錄，已追蹤至日誌專責模組。"},
    "IN": {"rule_ids": [], "reason": "未處理外部表單輸入，輸入驗證由另一控制器負責。"},
    "CR": {"rule_ids": [], "reason": "未配置加密運算或傳輸安全控制，已核對引用來源。"},
    "EH": {"rule_ids": [], "reason": "此檔未實作例外處理或錯誤輸出，已檢查呼叫鏈。"},
    "LG": {"rule_ids": [], "reason": "已閱讀檔案內容，未在此檔直接紀錄系統日誌。"},
    "DP": {"rule_ids": [], "reason": "未在此檔處理敏感個人資料，已檢查欄位與呼叫。"},
    "PD": {"rule_ids": [], "reason": "未配置部署管線、環境機密或憑證管理，已查核用途。"},
    "BC": {"rule_ids": [], "reason": "未實作備份或復原程序，已查核組件責任。"},
    "SI": {"rule_ids": [], "reason": "未實作套件更新與完整性控制，已核對程式內容。"}
  },
  "rule_reviews": [
    {"rule_id": "AC-01", "result": "review", "reason": "已檢查 Session 逾時與權杖檢查路徑，但部署時效資料尚待確認。", "line_start": 15, "line_end": 32}
  ]
}
```

> 上述只是格式示意，範例 SHA256 不是有效值。不可直接複製範例文字當審查證據。請依真實來源計算摘要與行號。

- 每檔應先依 `rules.json` 70 條規則逐一判斷可能適用的規則集合；同一檔案可以對應不同類別的多條規則。搜尋／關鍵字只用於尋找候選，**不能第一個命中即返回或自動回填某個 `XX-01`**。沒有命中某關鍵字也不等於不適用。
- 切勿混淆規則 ID：`AU-01`＝密碼強度規範、`IN-01`＝SQL Injection 防護、`DP-01`＝依賴套件安全性、`PD-01`＝個資蒐集合法性，均須以規則主檔為準。
- 新增可選的 `candidate_exclusions`：候選分析器發現實際安全語法，但人工核對後確認此檔不適用時，逐條記錄 `{"rule_id":"AC-08","reason":"具體說明已檢查的資源存取呼叫、負責元件與不適用原因（至少 40 字）"}`。不得以通用「無直接適用」替代，也不能自動產生排除理由。
- 強訊號候選未列入 `category_screening.rule_ids`／`rule_reviews`、且沒有上述具體排除理由時，來源完整性驗證會拒絕交付；候選是待追查線索，不代表漏洞或自動符合。
- `checks[].evidence` 若只有 `using`、註解、純宣告或括號行，不能作為 `completed` 的安全證據。對 `review` 須指出本規則已完成的靜態查核及明確缺少的外部工件，不可只列出「部署、政策或動態測試」清單。
- 十類 `reason` 須各自根據該檔案的控制責任撰寫，不可對多類別複製同一段制式不適用理由。大量檔案共用僅數字不同的摘要／結論模板也會被拒絕。系統**不因每檔只有一條規則而直接判定錯誤**；錯誤是未真正判斷其他適用規則。
- `category_screening` **十類不可缺漏**。`rule_ids` 列出本檔案真正適用且已執行的規則；其餘規則視為經篩選不適用，必須在該類 `reason` 說明控制責任。不能只是將同一預設敘述套到所有檔案。
- **自訂命名之安全控制**：固定方法名稱／業務欄位只是偵測線索；若已人工確認某規則（例如 AC-08）由非慣用命名的程式碼真正實作，`rule_reviews[]` 可加 `semantic_review`，包含 `control_behavior`（至少 40 字）、`call_chain`（至少 40 字）、`verification_method`（至少 20 字）。同一 `checks[]` 必須是 completed，且附有相同規則、相同檔案、與 `rule_reviews.line_start/line_end` 重疊的正式來源行號證據。片段須是真實可執行程式碼，仍須追查真正控制及繞過路徑；不可用來免除掃描工件、覆蓋率、Finding 或控制有效性檢驗。未提供明確人工複核及正式證據者，照常攔截不相關來源。
- **來源有效性不只看行號**：每筆 `rule_reviews` 及 `checks[].evidence` 的片段均會檢查是否只有註解、`using`、欄位／方法宣告或與選定規則明顯無關的控制。例如 `AU-01` 需密碼複雜度設定，`AU-08` 需雜湊機制佐證，`DP-01` 需套件風險掃描證據；不能單靠套件集中管理的設定便判 Pass。規則式檢查只能攔截明顯不合理片段，無法確認安全控制的完整性。
- **強制補查**：同一套固定文字排除多個 `candidate_exclusions` 會被拒絕；若掃描結果仍有 `review_integrity_errors`／`recheck_rule_ids`，即使 70/70 completed 也不得產生正式報告。保留既有 Finding 和有效歷史證據，必須真正重新核對原始碼、方法呼叫、設定及外部證據。
- `rule_reviews` 必須逐一覆蓋上述所有 `rule_ids`，記錄 `pass / fail / review`、具體理由及檔案內有效行號；同一檔案可以關聯多項規則，但**沒有固定最低項數**。無直接適用規則時可以是空陣列，十類仍要逐項判斷。
- 同一個 `rule_reviews[].rule_id` 必須已完成 `checks[].execution.state=completed`，且該檔案在該規則 `execution.inspected_paths` 中；反向亦同，禁止只靠路徑灌滿覆蓋率。
- **不適用（`na`）的檢查範圍例外**：`checks[].status=na` 且 `execution.state=completed` 時，`execution.inspected_paths` 可以包含為了確認規則不適用而實際閱讀的原始碼。這些是**檢查範圍**，不是「本檔適用規則」；不得因此將 `na` 填入 `category_screening.rule_ids` 或 `rule_reviews`，也不能改判 `pass`。Verifier 只對通過完整逐檔 SHA256、十類篩選與來源品質驗證的檔案承認此類關聯，且 `na` 規則自身須有具體判定理由、實際搜尋／閱讀方法與至少一筆可定位且有實質程式碼的 source evidence（須位於其已檢查路徑）。診斷的 `verified_na_inspection_paths` 會另外列出這些路徑，不計入適用的 `reviewed_file_rule_ids`。不符合者維持 blocker，不能直接從 `inspected_paths` 推定已驗證。

- `sha256` 需從實際來源內容計算，不可填 Git Revision 或事後任意編造。來源異動後必須重新檢查、更新雜湊與相關紀錄。
- **跨檔理由不得制式化**：若大量沒有 `rule_reviews` 的檔案，在相同安全類別重複同一個理由模板，完整性驗證會拒絕交付。要逐檔追查控制責任並寫明實際來源差異；抽樣（例如 20 檔）只能用來複核可信度，不能取代完整來源覆蓋。
- **覆蓋數字要對帳**：`eligible_file_count` 是全部未排除工作樹檔案，`reviewed_file_count` 是已驗證的逐檔紀錄；`source_file_count` 是必要審查的原始碼／設定檔，`missing_source_file_count` 只計算這個來源子集。正式報告 `eligible_unreviewed_files` 必須完整列出差額與原因，不得把 `missing_source_file_count=0` 解讀成所有 eligible 已審查。
- **SHA256 不符先調查、不可批次重寫**：執行 `python <SKILL_ROOT>/scripts/hash_audit.py --target <TARGET_ROOT>`（或透過 run-python 包裝程式）。工具只讀取來源與 assessment.json，分別列出 BOM／CRLF 相容、真實不符、無法讀取及不合法雜湊。真正不符須核對審查當時的 Git revision／來源版本並重新審查；不可直接以正規化雜湊覆蓋紀錄。
- **跨平台雜湊**：標準算法是對「移除 UTF-8 BOM、CRLF 視為 LF」後的內容計算 SHA256，使同一版本在 Windows（autocrlf 檢出 CRLF）與 Linux／macOS 得到相同值。取得方式：`sh "<SKILL_ROOT>/scripts/run-python.sh" "<SKILL_ROOT>/scripts/source_reader.py" --source-root "<TARGET_ROOT>" --path "<相對來源檔>" --digest`。驗證時**同時接受**舊版以原始位元組計算的雜湊（含 CRLF／LF、有無 BOM 的檢出差異），既有報告不需重算；空白、縮排或程式碼的實質異動仍會被判定為已異動。
- 舊的 `assessment.json`、Finding、既有外部證據仍須保留；缺少 `file_reviews` 僅代表此項完成證據不足，不得自行產出假資料補齊。

候選定位（不改寫報告或來源）：`python scripts/analysis_candidates.py --source-root <受測專案> --path src/Web/Controllers/AccountController.cs`；遇到 `candidate_exclusions` 必須人工核對控制責任，不得依訊號自動填寫排除或結論。

正式驗證：`python scripts/validate_assessment.py <受測專案>/reports/security-code-review/assessment.json --source-root <受測專案>`；最終執行 `complete_review.py --target <受測專案>`。在 Skill 執行環境中可用 `run-python.sh` 或 `run-python.cmd` 包裝呼叫。現有驗證可核對關聯、路徑、內容雜湊及行號，**無法獨立證明 Agent 曾實際閱讀或判斷是否正確**；審查人仍應抽驗結果。
