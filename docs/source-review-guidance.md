# 逐檔、跨檔與控制有效性的實作細則

完整模式在開始第一批來源閱讀前必讀；分類模式由 [分類審查操作契約](category-review.md) 指定對應的完整性規範。此文為操作指引，正式規則仍由 `rules.json` 與各自判定矩陣約束，不能憑指引文字自動形成安全結論。

## 審查資料完整性與中斷交易復原（完整模式專用）

新審查在來源索引與 `--init` 後自動封存起點；**既有審查**不得被自動信任，必須先核對 assessment、Finding、所有工作中證據與來源快照，才可明確執行 `review_safety.py --seal-integrity`。封存後多檔 JSON 必須透過 `--stage / --integrate` 的 SHA256 交易鏈更新，禁止直接覆寫既有已驗證結果；發生交易中斷必須先核對，執行 `review_safety.py --recover-integrity`。若受控檔案出現原版本及預期新版本以外的第三種內容，一律停止復原。完整性鏈不等於數位簽章，不能抵禦可同時改寫全部日誌的人。詳見 [證據完整性與安全復原](evidence-integrity.md)。

## 單代理審查完整性守門（完整模式專用）

**完整審查預設由主代理執行；可選擇讓子代理平行進行唯讀來源分析，但僅主代理能執行 `--stage`、`--integrate` 及正式判定與第二輪複核。** 沿用既有逐檔檢閱、70 項規則、真實證據與正式報告契約。完整操作與例外見 [完整性守門操作指引](review-integrity-guards.md)。

1. `analysis_prepare.py` 現會建立固定 Git Revision／全來源 SHA256 的 `analysis/review-snapshot.json`，以及 `structure-index.json` 的 `typed_relationships`。候選包含 DI、設定引用、Middleware、Endpoint 授權、跨專案引用及方法呼叫；新版 Roslyn 提供語意符號及介面分派候選，無法解析時保留完整同名方法清單，不得截斷候選。所有呼叫點與邊皆僅供定位，需閱讀來源查證，並補查反射／動態設定等無法可靠建立的關聯。
2. 先閱讀 [效能與唯讀分工指引](review-performance.md)，使用 `review_queue.py --compact` 取得短待辦、`file_review_skeleton.py` 批次核對來源 SHA256 與索引提示；此輸出不是已讀證據。接著呼叫 `review_safety.py --target "<TARGET_ROOT>" --plan` 取得 70 項的 `local / cross_file / project` 最小責任範圍；**所有 `project` 規則都要查核，即使來源完全沒有命中**。不得以「查無關鍵字」推定不適用。每個來源檔仍要評估全部 70 條規則的適用性。
3. 逐檔審查及規則結果先以 JSON 分批透過 `review_safety.py --target "<TARGET_ROOT>" --stage "<JSON路徑>"` 暫存，再以 `--integrate` 整合；整合工具只保存與衝突檢查，不會替 Agent 做安全結論。**所有正式結果仍只能由整合後的 assessment.json 與原有驗證器交付**。舊 Findings 不可覆寫／刪除；不同結果需重新核對，而非任取最後寫入值。
4. 每條 `cross_file`／`project` completed 規則必須另外完成 `analysis/rule-closures.json` 結案紀錄，包含實際追查來源、控制責任、全域搜尋、跨檔關聯、可能的繞過路徑與未解補查；`open_issues` 非空、只有單一來源卻未說明其他關聯、責任或搜尋不明時**不得 completed**。新版索引亦要求透過 `callsite_reviews` 對相關呼叫點逐一以來源證據核實或具體排除，未處理或歧義未解者不得結案。靜態確定的缺陷直接 fail＋Finding；外部缺口依既有判定階梯處理。
5. 來源版本異動會阻擋佇列完成和正式報告。Agent 必須核對變更後明確執行 `review_safety.py --target "<TARGET_ROOT>" --snapshot-refresh`，再重建分析索引並重新檢核已完成的受影響判斷；沒有可驗證完整依賴閉包時，保守重審全部 completed 規則。刷新保留既有 Findings，不代表既有 pass 自動仍有效。
6. 先執行 `--begin-second-pass`，由同一代理完成全部 70 項實際反向複核；矛盾未裁決或證據缺漏均不得交付。
7. 最後執行 `review_safety.py --target "<TARGET_ROOT>" --validate` 並確認 `review_queue.py` 的 `safety_integrity_errors=[]`、`ready_for_report=true`，才可執行 `complete_review.py`。既有 `file_reviews`、70 項完成證據及來源覆蓋驗證不放寬。

## 跨檔控制鏈證據守門（必須執行）

針對需跨檔確認控制責任的規則，必須以 `closures[rule_id].control_trace` 記錄真實的入口、控制執行、資料操作或設定節點，以及經來源查證的索引關聯；`examined_relationship_ids` 必須與附證據的 `control_trace.relationships` 相同。呼叫點 verified／excluded、候選關聯排除都要有來源行號、核對理由和具體繫結／排除分類；不可把所有索引候選標為 excluded 或把全案 `examined_paths` 當成已驗證呼叫鏈。若實際是單檔控制或完全外部責任，明確記錄邊界，不捏造跨檔證據。所有控制鏈來源需與正式檢核 `execution.inspected_paths` 及檢核證據一致。

新索引會啟用此驗證；舊索引及既有 Findings 不自動改判。來源變更時保守重新審查，不得僅補填 JSON 以通過守門。操作格式見 [完整性守門操作指引](review-integrity-guards.md)。

## 安全控制有效性與繞過路徑驗證（必須執行）

每條適用規則除了確認安全機制存在，還須從真實程式碼核對 **入口 → 控制執行分支 → 受保護操作**、拒絕分支及可替代／繞過路徑。不能因 `[Authorize]`、`UseAuthorization()`、參數化 API 或雜湊 API 存在就直接 pass。對介面實作、DI、環境覆寫、匿名入口、直接 Repository 存取與重放路徑應以反向攻擊視角逐一追查。

`review_queue.py --detail-id <RULE_ID>`（分類模式同時指定 `--categories`）的 `control_effectiveness_guidance` 指定最低繞過情境；靜態／混合規則判 `completed + pass` 時，必須於 `review_safety.py --stage` 的批次 JSON 中提供 `control_verifications`，記錄 `entry_points`、`enforcement_points`、`protected_operations`、`control_condition`、`failure_behavior`、`search_summary`、`bypass_scenarios` 與 `open_issues=[]`，並經 `--integrate` 保存為 `analysis/control-verifications.json`（此為完整模式路徑；分類模式經 `review_queue.py --categories <分類> --stage/--integrate` 保存於各自 `partial/<分類>/analysis/`）。證據路徑、行號及雜湊均需核對當次來源快照；`enforcement_points` 至少一筆須對應正式規則來源證據。情境未查或有未解的繞過不得判 pass；不要填模板、虛構不存在的攻擊測試，也不得用 `review` 迴避尚未完成的靜態調查。外部規則維持原判定階梯與外部工件驗證要求，已確認缺陷仍是 `fail`＋Finding。

跨檔呼叫鏈驗證與安全控制有效性驗證互為補充，兩者皆非自動安全判定。完整欄位及示例見 [安全控制有效性驗證指引](control-effectiveness-review.md)。

## 待確認判定與外部證據驗證（必須執行）

任何 `completed+review` 均須先證明：已完成儲存庫內應完成的程式碼與設定追查、目前沒有足以直接 `fail` 的靜態缺陷、缺少的外部資料**真正會影響本規則判定**，且已指名可核對的工件。不能因缺少非必要動態／邊界測試、未完成呼叫鏈分析或缺乏使用者提供的權限矩陣而 `review`。已證實弱點直接 `fail`＋Finding；查核未完成則保留 `pending/blocked`，不以 `review` 代替。

以 `review_queue.py --detail-id <RULE_ID>`（分類模式同時指定 `--categories`）取得 `decision_adjudication_guidance`（原有 `decision_guidance` 不變）。判定 `completed+review` 時，於 `review_safety.py --stage` 的批次 JSON 加入 `decision_audits`，由 `--integrate` 保存 `analysis/decision-audits.json`（分類模式經分類佇列的 `--stage/--integrate` 保存於各自 `partial/<分類>/analysis/`）；記錄已讀來源及行號、靜態已確認部分、實際外部工件、`blocking_question`、為何只有該工件能決定結論、完整來源快照與 `open_static_questions=[]`。外部控制可依矩陣使用 `external_only`；靜態／混合規則只可用 `static_done_external_pending`。批次／正式驗證均不會依審查紀錄文字自動改判，缺少必要證據不能結案。格式見 [待確認判定指引](review-decision-adjudication.md)。

## 判定品質守門（本次選定規則，完整模式為 70 項）

對任何 `completed + review`，先判定核心程式碼控制是否確實失效、成立或仍未追查。不得用 `RULE-ID-deployment-or-policy-evidence` 類佔位符代替外部資料；需記錄具體工件、責任單位及外部條件成立／不成立時的**不同判定**。若僅是假設可能存在未知組織政策，不得阻擋已能由程式碼判定的規則；確有政策邊界時，須記錄可核對的政策識別與本系統適用依據。安全控制缺陷優先 `fail`＋Finding，不因還缺政策或測試就保留 `review`。

此功能新增 `decision_quality_version=1` 與外部缺口的結構化判定分支；沿用既有 `assessment.json` 與來源快照、整合及第二輪流程，不會自動更改舊結果。完整格式與遷移方式見 [待確認判定指引](review-decision-adjudication.md)。

## 已完成 Fail／Review 的控制有效性證據（必須執行）

新版來源索引的 `control_outcome_version=1` 會對適用的安全控制要求：`fail` 使用真正的缺失位置、至少一個已確認的繞過情境與正式 Finding 連結；`review` 必須完成程式碼控制與必要反向情境驗證，且指出與既有裁決紀錄一致、真正會改變判定的外部工件。原本 `pass` 的控制存在性與繞過守門不變，純外部控制不須捏造程式碼控制鏈；禁止以欠缺非必要測試遮蔽已證實的缺陷。所有結果皆由主代理閱讀程式碼後提出，不得由驗證器自動改判或生成 Finding。詳見 [安全控制有效性指引](control-effectiveness-review.md)。

## 單代理第二輪反向複核與矛盾裁決（完整模式專用）

第一輪完成全部 70 項規則、100% 來源檢閱及跨檔／控制有效性／外部判定證據後，**不得直接交付**。執行 `review_safety.py --target "<TARGET_ROOT>" --begin-second-pass`，固定第一輪全部判定指紋及 Git／來源快照到 `analysis/first-pass-baseline.json`。同一主代理必須**重新閱讀來源**，以攻擊者角度挑戰每項結論，對全部 70 項提出反例假設；高風險規則至少核對兩個不同攻擊面。這是分階段的自我複核，**不是獨立代理或盲審**，不得宣稱真正獨立性。

以 `review_queue.py` 的 `second_pass.pending_ids` 繼續，`--detail-id` 取得 `adversarial_guidance`；將真實反向搜尋、攻擊假設、核對結果與來源證據寫入 `adversarial_reviews`，並以 `review_safety.py --stage/--integrate` 保存。若發現矛盾，必須先依法修訂原檢核與 Finding，再以 `contradictions` 說明來源、修訂原因及結果，不能只寫「已複核」。70 項第二輪證據齊備且 `review_safety.py --validate` 與 `ready_for_report=true` 後才可產生報告。詳見 [第二輪反向複核指引](adversarial-second-pass.md)。

## 第二輪實質反例與矛盾裁決守門（本次選定規則）

對新版索引的每條完成規則，第二輪需先對照不可變的第一輪 `decision_reason`，重新閱讀關鍵入口、控制分支、拒絕行為或真正的外部工件，提出可反駁的攻擊假設。每個 `hypotheses[]` 須記錄攻擊向量、前提、預期破壞、重查方法、實際行為與重新閱讀證據；高風險規則至少兩種真正不同的向量。禁止以 `RULE-ID-adversarial-surface-1/2`、相同攻擊敘述、重複同一來源行而無說明來完成複核。第二輪發現漏報或誤判時，依法修訂判定與 Finding，記錄最初漏查原因及裁決；第一輪錨點不可覆寫，確認與修訂須區分。純外部控制不得虛構程式碼攻擊路徑，使用真實外部證據複核即可。完整格式見 [反向複核指引](adversarial-second-pass.md)。

## 逐檔與 70 項多規則審查細則

1. 讀取 `standards/standards-register.yaml`、`policies/applicability-matrix.yaml`、`policies/review-decision-matrix.json` 與 `rules/{AC,AU,IN,CR,EH,LG,DP,PD,BC,SI}.yaml`，共 70 項；不得跳過、增加或重編 ID。
2. 盤點 `TARGET_ROOT` 的語言、框架、認證授權、資料流、儲存、相依套件、部署與 CI/CD；根據 `profiles/project-profile.example.yaml` 辨識適用情境。排除 `.git/`、`reports/`、`.agents/skills/`、`.claude/skills/` 與生成物／相依套件目錄，避免把 Skill 本身當成受測程式碼；不要排除專案的 CI 設定。缺乏政策資料時不擅自決定法規適用級別。
3. **必須按前述佇列迴圈逐項完成 70 項檢核，不能只填入 70 個 ID 或一律設為 review 就結束。** 逐檔／規則紀錄應先使用 `review_safety.py --stage`、`--integrate` 完成無衝突保存；跨檔及全專案結案檢查通過前不可交付。 依每條規則的 `inspection.search_targets`、`applicability` 與證據要求搜尋目標專案、追蹤程式碼呼叫鏈並核對組態；可分批掃描，但必須持續直到 70 項各自完成，才允許產製報告。一次呼叫應自動持續，不因找到高風險問題而暫停。每完成一組就將結果保存到受測專案的 `reports/security-code-review/assessment.json`，重新啟動時先載入已查核結果並僅補做尚未完成的 ID；不得憑空標記完成。
   - **先查跨檔案候選**：在逐檔判斷 `file_reviews` 適用性時，可執行 `scripts/analysis_candidates.py --source-root <TARGET_ROOT> --path <來源相對路徑>`，取得保守的 .NET 安全規則候選；必須實際追查方法、資料流、呼叫鏈和相關設定，建立多對多關聯。同檔可屬多規則，同規則也可有多檔；不可各選一個代表檔案，亦不得機械式將所有候選判為 pass/review。若高信心候選經核對不適用，在該檔 `candidate_exclusions` 明確逐條記錄不適用原因，禁止複製制式文字。候選只是定位輔助，不保證資料流正確。
   - **個別規則與個別片段重新核對**：每個 `file_reviews[].rule_reviews` 的行號必須定位到該規則的實際安全控制語句、資料流判斷或明確設定；不可只引用 `using`、屬性、欄位或 Handler 類別繼承。尤其 `AU-01` 不能用郵件 Token URL；`AU-08` 不能只用 UserManager 欄位；`PD-07` 不能用 JWT Service 欄位；`DP-01`、`DP-04` 不能只引用 `ManagePackageVersionsCentrally`；`SI-01` 不能用 .devcontainer 的 remoteUser。這些正向關鍵字也不是通過保證，必須實際核對安全條件及效果。
   - **候選排除不得制式複製**：遇到 `ValidateAsync`、`ValidationException`、授權決策或實際上傳控制，不能以「只有型別宣告」排除；跨檔同文套用的 `candidate_exclusions` 應重新調查。若 70 項均為 `completed` 但品質檢查失敗，`review_queue.py` 會從 `recheck_rule_ids`、`next_checks` 重新列出規則，必須繼續檢核；`completed` 和 `pass` 不得自行修改或自動重置既有 Finding。
   - **判定矩陣優先**：`decision_guidance.mode=static` 以來源／設定為主要證據，完成靜態查核後必須給出 `pass`／`fail`，不得因沒有動態測試而 `review`；`hybrid` 先依程式碼給出結論，僅在 `manual_boundary` 所列事項確實阻斷結論時才 `review`，`expected_evidence` 中的測試為建議佐證，缺少不構成 `review`；`external` 的 `pass` 必須有真實部署、制度、測試或相應組態工件，缺工件時可 `review`，但來源已證實的缺陷仍須 `fail`。`pass_condition`、`expected_evidence`、`manual_boundary` 必須按規則逐條核對，不得機械把 70 項轉成 pass 或 review。
   - **嚴格排除弱證據**：`using`、註解、單獨的方法／類別宣告、空括號及初始化入口等不可作為安全控制符合的唯一來源證據；需要可核查的實際控制邏輯、判斷分支或工件。 `review` 必須明確列出已執行的靜態步驟和本規則實際缺少的資料，不能套用「部署設定、正式政策、運作紀錄或動態測試」清單。
   - 對每項填寫 `execution: {state, methods, summary, inspected_paths?}`；掃描中為 `pending`，已實際執行檢核才標 `completed`，出現無法進行的真正錯誤標 `blocked`。
   - **實際案例**：AC-01 要追查 `Program.cs` 到 Cookie／Session／JWT 過期組態及伺服端檢查，不能只引用 Refresh Token 行；若來源已明確顯示與適用閒置期限衝突，先記錄可證實的 `fail`，不強制要求邊界實測才能記錄發現。AU-09 必須查 MFA 啟用與繞過分支；IN-07 要追查外部路徑輸入至檔案 API；PD-02 必須追查顯示／匯出遮蔽，不能只引用 IDNo 欄位；BC-03 必須有高可用部署或演練證據；DP-01 須查明依賴清單及漏洞資料，不得只引用集中版本管理開關。
   - `status` 仍為 `pass`、`fail`、`review` 或 `na`，判定依「共同證據與結果判定」的階梯。**pass**：控制已由證據證實；**fail**：靜態程式碼或儲存庫內容已能證實缺陷或控制缺席，建立 Finding，勿等待動態測試；**review**：僅限「可接受的 review 缺口」且已指名工件；**na**：明確查證不適用及其控制責任。不得把靜態可判定的檢核預設為 review，也不得強制某個 pass/fail 比例。
   - **完成狀態必須具備逐條證據**：對 `pass/fail/review`，除了 `execution.inspected_paths`，每項 `checks[].evidence[]` 至少要有可定位的真實來源路徑與行號，或可追查的設定／測試／部署工件。單純把路徑掛在已完成規則、只有 `kind=other` 的空泛描述、或由搜尋字串推定安全結論，均不得標 `completed`。跨檔案證據須保持對應，重要否定性結論須說明搜尋與控制責任分析範圍。
   - **不要為通過檢查而虛構工件編號或隨意改寫模板**：實際沒有可定位證據時保留 `pending` 或 `blocked`，列出未完成原因並繼續可執行的其他檢核；已完成但缺外部佐證才用 `review`。每條規則的摘要、結論、證據描述須對應其真正的控制內容，不可只替換規則 ID／檔名／行號／數字。
   - **審查是識別風險並產出報告，不是修復程式。** 發現密碼鎖定、例外訊息、TOTP 或任何疑似漏洞時，立即將已確認風險保存為 `assessment.findings[]`、將相應檢核狀態更新為 `fail` 或證據尚不足時 `review`，並保存檔案、行號、佐證、影響、改善建議與信心水準。接著**繼續剩餘檢核**，不得把「需要優先處理／修復」當作停止掃描、要求使用者先改程式或提前交付部分結果的理由。風險優先級僅用於最後報告排序，所有改碼與修補皆屬後續獨立工作。
   - **Finding 與狀態必須連動**：信心為 `confirmed` 的 Finding，其 `check_ids` 中至少一個主要規則必須記 `fail`（不可停在 `review`，也不可為 `pass`）；`fail`／`pass` 的 `decision_reason` 不得寫「保留 review」。驗證器會拒絕這類矛盾。
   - **品質守門**：正式驗證與佇列重審會套用 `scripts/lib/review_decision.py` 的 70 項矩陣與弱證據辨識，拒絕單純 `using`、`namespace`、屬性、參數識別符，以及已知制式化審查理由。驗證器是最低限度守門，通過驗證也不證明真實控制有效。若被標記 `recheck_rule_ids`，必須重新閱讀實際控制流程、補足真實證據，不能只更換理由字串。
   - **`review` 需分類**：每個 `review` 須加上 `review_kind`——`external_only`（本質上需外部或制度證據）或 `static_done_external_pending`（靜態部分已有明確結論，僅其中一項外部條件待補；`decision_reason` 須先寫靜態結論，再以「待確認：」列工件）。靜態部分若已含缺陷，不得使用本分類，須改 `fail`。報告會分開統計；`review` 比例準則見「共同證據與結果判定」。
   - **建立 Finding 前的自我檢查（驗證器會抽查其中可機械判斷者）**：
     - **追查使用處**：引用某變數或方法作為風險證據前，確認它真的被傳出、儲存或執行；宣告後從未使用的變數是死碼，不是風險路徑。驗證器遇到 Finding 點名（以名稱或單行行號）的局部變數在檔案中只宣告一次，會拒絕；已追查確實有使用時，於 `verification.usage_traced` 說明。
     - **讀相鄰註解與文件**：判定前先讀引用片段前後的註解、README 與設計文件，已說明的刻意設計或已知限制要納入判斷（如供應商不支援 SRI、標頭明確標為選配），並於 `verification.design_notes` 記錄；驗證器對片段附近含說明性註解者警示。
     - **標示 `impact_type`**：`confidentiality`／`integrity`／`availability` 擇一或多個，嚴重度須對應。僅影響可用性（例如驗證流程永遠失敗而非被繞過）不宜列為 high；僅有可用性且為 high／critical 時驗證器警示。
     - **證據要點出具體欄位**：日誌、個資、機敏資料類 Finding 須列出實際受影響的屬性或欄位（例如 `UserLoginCommand.Password` 經 `{@Request}` 寫入 Serilog），不可只寫「完整 request 物件」。
     - **部署假設不是 Finding**：僅因「程式碼看不出部署層有無限制」（如來源網路、VPN）而無具體缺陷時，記為對應規則的 `review` 並寫明待補工件，不建立 Finding。
   - 僅在通過「標記 `review` 前的自檢」三題時才標記已完成靜態查核的 `review`，並說明仍待確認的範圍；不得因該項缺證據而停止其餘檢核。
   - **唯讀解碼已獲本 Skill 的一般執行授權，不得再次詢問使用者可否讀取 CP950／CP1252。** 先依 BOM 使用 UTF-8-BOM／UTF-16 等編碼，無 BOM 優先 UTF-8，失敗則自動嚴格回退 CP950、CP1252。回退警告只需記入診斷／報告限制，**不是人工確認閘門**；疑似誤判編碼時以其他線索核對，不得默默扭曲證據。可使用 `sh "<SKILL_ROOT>/scripts/run-python.sh" "<SKILL_ROOT>/scripts/source_reader.py" --source-root "<TARGET_ROOT>" --path "<相對來源檔>" --start 1 --end 200`（Windows 以 `run-python.cmd` 搭配 `source_reader.py` 執行） 取得帶行號的唯讀內容，不得修改來源、忽略解碼錯誤位元組或憑空填證據。
   - 如果個別來源仍無法安全解碼，記錄檔案與解碼錯誤並繼續其他可讀檔案與檢核；只有對完成剩餘審查構成實質阻斷的錯誤才能中斷，並清楚列出未完成範圍。
   - 不得自動執行破壞性測試；所有結論與外部證據遵循「共同證據與結果判定」。
### 必須記錄審查範圍與檔案明細

- 在 `assessment.scope_details.projects` 記錄真正納入的專案：每項具有 `name` 及相對 `TARGET_ROOT` 的 `path`；單一專案可使用 `path: "."`，多專案各列一筆。不要由 manifest 數直接推定審查專案數。`--init` 會依 `.csproj` 預填此清單；也可執行 `scope_inventory.py --target <TARGET_ROOT>` 取得。盤點到 `.csproj` 卻未宣告時，驗證器會拒絕交付；漏列的專案會警示。
- 在 `scope_details.excluded_paths` 可記錄額外排除的目錄／檔案及 `reason`；不得排除仍被列為已審查的檔案；專案 CI 設定不能預設排除。
- 每項 completed 規則，將**實際閱讀、追蹤與核對**的相對來源路徑填入 `execution.inspected_paths`；單純搜尋命中或盤點檔名不算已審查，不能大量填入尚未實際閱讀的路徑。此清單**不是逐檔完成的獨立證據**。
- 逐檔審查須同步寫入 `assessment.file_reviews[]`（詳見 [逐檔資料契約](file-review-contract.md)）：來源 SHA256（以 `source_reader.py --digest` 取得，忽略 BOM 與 CRLF／LF 差異）、內容導向摘要、已執行方法、AC／AU／IN／CR／EH／LG／DP／PD／BC／SI 十類規則的適用性篩選與理由，以及適用規則的逐條結論、實際行號；與 `execution.inspected_paths` **雙向一致**。不能照檔名、規則 ID 或副檔名自動填結論，也不能以預設全數「不適用」替代閱讀。
- **P4 逐檔可信度**：各檔案的十類篩選理由須依實際內容與控制責任撰寫；大量無 `rule_reviews` 檔案沿用同一句的情形會被完整性驗證拒絕交付，不可由 Agent 改寫同義模板規避。`eligible` 是全部未排除檔案，不等於 `source_file_count`，報告須完整列出未列入實際審查清單的檔案與原因。SHA256 失配時先用 `scripts/hash_audit.py --target <TARGET_ROOT>` 唯讀調查，BOM／CRLF 相容已由驗證器處理，不可未核對來源版本就批次重算。
- **禁止「第一個命中即返回」的單一關鍵字分類器。** 對每個檔案需檢查所有 70 項規則的真正適用條件，先建立可能相關的候選清單（可能跨類別、同一類別多條），接著逐條追查實作、呼叫鏈與組態，再將**全部確實適用且已檢核的規則**列入 `rule_reviews`。不能 `return`／`break` 於首次命中後，也不能把未命中的檔案預設掛 `SI-01`，不能硬性要求每檔多於一條規則。
- **按規則主檔辨認真正含義**：以 `rules.json` 的 `id`、`title`、`inspection`、`applicability` 為準，不可自行以字首或關鍵字隨意指定 `XX-01`。例如 `AU-01` 是密碼強度規範，不是稽核事件；`IN-01` 是 SQL Injection，不是所有輸入驗證；`DP-01` 是依賴套件安全性，不是個資；`PD-01` 是個資蒐集合法性，不是部署設定。
- `category_screening.reason` 應描述**本檔案中該類控制的責任、已檢查的具體實作或為何無直接相關控制**；同一句「未見此檔直接實作該類控制」不能複製到不同類別。逐檔 `summary` 與每條 `rule_reviews.reason` 不得只變更行數、檔名、規則 ID 就大量生成。驗證器會拒絕這種制式紀錄；不得為通過驗證而亂補規則。
- 既有 `assessment.json`、`file_reviews`、Finding 與證據應先讀取保留。發現模板化紀錄時必須**重新閱讀對應來源並完整補查適用規則**，不允許僅以程式批次加上其他關聯 ID 來修正報告。
- 不適用類別仍須記錄具體理由；完全沒有直接適用規則的檔案可填 `rule_reviews: []`，但必須完成全部十類判斷與實際來源核對。**不是要求每個檔案關聯多個規則**，而是要求每個適用的關聯都有可核對依據。
- `complete_review.py` 自動盤點工作目錄、計算排除數，**僅從通過逐檔完整性驗證的 file_reviews** 計算已審查來源數、專案數與檔案明細；來源異動、規則關聯／行號不一致、漏查任何類別時禁止正式交付。無專案對照時應標示「未提供」而非猜測數字。

### 必須完成逐檔來源覆蓋，才可交付 70/70 報告

- `review_queue.py` 輸出的 `source_coverage` 提供應審查來源總數、已審查數、未審查數與副檔名分布；`next_source_paths` 每批列出最多 30 個未審查檔案。**全數 .cs（含指定目錄深層子目錄）都要實際閱讀、分析並記錄**；`.razor`、`.cshtml`、設定檔及其他來源類型也要核對。不得只取前 13 個或抽樣冒充全部完成。
- 70 項規則可與逐檔盤點並行，應先完成來源清單，依檔案實際內容檢查權限、輸入、資料流、敏感資訊等；完成單檔後才可將路徑寫入相關規則已完成檢核的 `execution.inspected_paths`，並更新該規則的決策及 Finding。檔名搜尋命中不算閱讀，不得自動一次填滿 660 個路徑。
- 70 個 `execution.state=completed` **且** `source_coverage.missing_source_file_count=0` **且** `review_integrity_errors`、`rule_integrity_errors` 均為空，才能使 `ready_for_report=true`；必須提供實際 `TARGET_ROOT` 作來源驗證。當 70 項已完成但仍有未讀檔案，應繼續按 `next_source_paths` 逐檔補查、必要時重新審查已完成規則，不能直接進入報告階段；產生器及驗證器會拒絕來源覆蓋不足的報告。
- 僅可排除預設第三方套件／建置產物目錄，以及 `scope_details.excluded_paths` 明確記載、可辯護且不屬於本次審查的範圍；`scope_details.projects` 用於統計，不可用來偷偷縮小應審查檔案範圍。
- **交付前主動檢查**：大量同質 review、重複證據、錯誤規則對應、已證實弱點卻未建 Finding，以及 completed 但缺真實證據的規則。只可重新閱讀原始碼與補查佐證，不能僅修飾 JSON 通過驗證。機械驗證無法證明 Agent 確實閱讀程式碼；必要時應由審查者抽驗。
- `status=review` 須列出已核對的來源／設定及以「待確認：」指名的外部工件，不能把 `review` 當成尚未分析的預設結論；交付前對全部 `review` 重跑三題自檢，不通過者改判 `pass`／`fail`。
