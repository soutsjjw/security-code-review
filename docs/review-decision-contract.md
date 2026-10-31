# 共用證據與 Pass／Fail／Review／NA 判定細則

完整審查與指定分類審查都必須**在第一條規則做判定前**讀取；每次判定仍需依 `review_queue.py --detail-id` 的該規則矩陣獨立核對。`SKILL.md` 只保留硬性摘要，本文件保留全部判定階梯、允許的外部證據缺口及 Review 三題自檢。

## 共同證據與結果判定（所有規範均適用）

**核心原則：結論由程式碼、設定與儲存庫內容決定；`review` 只用於「即使完整讀完儲存庫仍無法回答」的規則。** 不得推測已通過或虛構已執行的掃描；`na` 必須有已核對的不適用理由；70 項規則的狀態、標準對照、正式分級與附件獨立驗證不得彼此推論為符合性結論；既有 Finding 與有效證據不可刪除。

### 判定階梯（每條規則依序判斷，取第一個成立者）

1. **`fail` + Finding**：來源／設定／呼叫鏈已證實缺陷、規則間矛盾、不安全預設值，或規則要求的控制在儲存庫中應有而不存在（須記錄搜尋範圍與責任分析）。控制存在但不完整者同為 `fail`，以較低嚴重度表達。
2. **`pass`**：適用控制已由實際控制邏輯、設定與呼叫鏈證實有效，且符合該規則 `pass_condition`。
3. **控制成立但缺測試／文件**：依控制本身判 `pass`（或第 1 項 `fail`），在 `decision_reason` 註明「儲存庫無對應測試」，必要時建立 Low／Info Finding；**不得因此 `review`**。`pass` 理由若寫到改善建議（例如「建議縮短 Token 有效期」）、未使用的安全元件或只在開發環境的弱設定，須另建 `info` Finding 關聯本規則，驗證器會拒絕含「建議」卻無 Finding 的 `pass`；`info` Finding 不改變 `pass` 結論，等級判定見下方「弱點等級判定」。
4. **`review`**：僅限下列「可接受的外部缺口」，且須指名所缺工件。
5. **`na`**：已核對不適用理由與控制責任歸屬。

### 弱點等級判定（Finding `severity`）

等級由 Agent 依實際證據逐筆判定，規則本身不預設等級；只有高／中／低／資訊四級，不設重大。

| 等級 | 判定基準 | 關聯規則狀態 |
|---|---|---|
| `high`＝高 | 可直接被利用造成機密性或完整性損害，例如授權繞過、注入、機敏資料外洩、可偽造憑證 | `fail` |
| `medium`＝中 | 已證實缺陷，但利用需特定前提或影響有限，例如控制不完整、不安全預設值需搭配其他條件 | `fail` |
| `low`＝低 | 已證實缺陷，但影響輕微、只影響可用性或已有補償控制，例如錯誤訊息透露少量內部資訊 | `fail` |
| `info`＝資訊 | 程式碼本身沒有錯，執行上也沒有立即的安全或效能風險，但不符合現代寫法或慣例，或屬於提供給開發者的技術債提醒 | `pass` 或 `fail`，不可為 `review` |

**主動記錄 `info`**：逐檔審查時遇到下列情形，即使規則判 `pass`，也要建立 `info` Finding 關聯最相關的規則，並附來源行號與改善方向，不可為了避開驗證而把改善建議從 `decision_reason` 刪掉：

- 使用已過時或標記 `Obsolete` 但目前仍安全的 API、寫法或套件用法（例如舊式 `WebClient`、同步 I/O 包裝非同步呼叫）。
- 安全控制有效，但寫法分散、重複或硬編碼，日後容易改漏（例如各 Handler 各自複製授權判斷、魔術字串角色名稱）。
- 未使用的安全元件、只在開發環境啟用的弱設定、註解掉的設定區塊，以及可再收緊但目前仍合理的參數（例如 Token 有效期）。
- 缺少對應測試或文件，但控制本身已證實有效。

`info` 不是缺陷：不得用來淡化已證實的弱點，已證實可利用者依上表判 `low` 以上並將規則記 `fail`；也不得為湊數量而建立沒有具體來源行的 `info`。

### 可接受的 `review` 缺口（須指名具體工件）

- **部署拓撲／主機**：防火牆、VPN、反向代理與 TLS 終止、AppPool／容器／服務帳號、主機 ACL、實際 HTTPS response。
- **營運與制度紀錄**：備份與還原演練、DR 演練、告警接收與值班、事故通報、法務核准、保留與輪替政策核定。
- **儲存庫外的平台設定**：branch protection、集中日誌平台、正式 secret provider 內容、雲端／資料庫設定。
- **規則 `manual_boundary` 所列且確實阻斷結論的事項**（例如逾時長度是否符合組織政策）。
- **無法取得的掃描結果**：已嘗試執行（如 `dotnet list package --vulnerable`）而因環境失敗者，須記錄指令與錯誤；未嘗試不得列為缺口。

### 不得作為 `review` 理由

- 缺測試（含逾期重放、邊界、整合、授權測試）。判定矩陣 `expected_evidence` 所列測試為建議佐證，**缺少不構成 `review`**。
- 缺角色／權限／ownership 矩陣：Agent 須逐 Controller／Handler 讀碼自行建立，不得要求使用者提供。
- 自承尚未完成的盤點（資料流、Handler／Repository 清單、反序列化點）：應完成後再判定；無法完成時 `execution.state` 保持 `pending`／`blocked`，不得標 `completed`＋`review`。
- `decision_reason` 已描述缺陷、矛盾或不安全預設值（如演算法不一致、清空 `KnownProxies`、`DateTime.Now`、註解掉的標頭、固定金鑰路徑、placeholder 密碼）：必須 `fail`。
- 自述缺陷的 `review` 理由由驗證器攔截，例如「空 catch 吞掉」「未設定 retainedFileCountLimit／保存期限」「無清理機制」「金鑰存放本機 C:\…」「沒有個資刪除功能」；控制責任即使在部署端，儲存庫內的缺陷仍須 `fail`。
- 「無法證明」「未見控制」類措辭：須改寫為明確結論（控制缺席＝`fail`，控制存在＝`pass`）。
- 儲存庫中通常以檔案表達的控制缺席（CI 設定、相依更新設定、安全標頭實作、稽核寫入、rate limit、log 保留組態）：記 `fail`，並註明「若於平台層另有控制，提供工件後可更新」，不以 `review` 迴避。

### DP-01／DP-04 的掃描證實相依弱點（只支持 `fail`）

受測專案沒有 Dependabot、Renovate 或 CI 掃描設定時，Agent 實際執行的掃描輸出加上套件清單的實際行，可以作為 DP-01／DP-04 `fail` 的完成證據；這條路徑**不能支持 `pass` 或 `review`**，套件清單行也不能證明已有掃描機制。條件全部成立才接受（`scripts/lib/dependency_scan_evidence.py`）：

1. **規則與判定**：只限 DP-01、DP-04；`checks[].status` 與該檔 `rule_reviews[].result` 都必須是 `fail`，並已建立 Finding。
2. **來源檔**：`**/packages.lock.json`、`Directory.Packages.props`、`*.csproj`、`libman.json`、`package-lock.json`。
3. **片段內容**：`rule_reviews` 或 `checks[].evidence`（kind=source）的行號範圍最多 30 行，且須解析出「套件名稱 + 解析版本」，例如 lockfile 的 `"System.Security.Cryptography.Pkcs": {` 與其下 `"resolved": "10.0.0"`；`<PackageReference Include="X" Version="1.2.3" />`／`<PackageVersion …>` 的版本須為字面值，`$(變數)`、版本範圍不算。只引用 `ManagePackageVersionsCentrally` 等集中版本開關解析不出套件，一律拒絕。
4. **掃描工件**：同一 `checks[].evidence` 至少一筆 `{"kind":"scan","artifact_id":"scan:<名稱>","sha256":"<64 位小寫十六進位>"}`。`scan:<名稱>` 對應受測專案 `reports/security-code-review/artifacts/scan-<名稱>.txt`（或 `.json`，兩者不可並存），例如 `scan-dotnet-list-package-vulnerable-20261031.txt` ↔ `scan:dotnet-list-package-vulnerable-20261031`。名稱只用小寫英數與連字號；工件不可為 symbolic link。
5. **SHA256**：`sha256` 須等於工件原始位元組的 SHA256，記錄在受 `integrity-manifest`／Journal 納管的 `assessment.json` 內，所以工件變更或證據被改寫都會被發現。任一筆 `scan:` 工件不存在、SHA256 不符或內文不合格，整條路徑拒絕。
6. **工件內文**：須是實際命令輸出，含 `has the following vulnerable packages`、`has the following updates to its packages`、GHSA／CVE 識別碼，或 outdated 的 `Resolved`／`Latest` 欄位標頭之一；片段的套件名稱與版本須出現在工件**同一行**。只寫描述文字不算。
7. **Q3**：`control-verifications.json` 的 `failure_points` 可指向該套件清單行，仍須與 `checks[].evidence` 及 Finding evidence 行號交集；`bypass_scenarios` 至少一條 `confirmed_vulnerability`，情境為 DP-01 的 `vulnerable_dependency`／`transitive_dependency` 或 DP-04 的 `unsupported_version`／`unpatched_dependency`，其 evidence 指向同一套件清單行。

`review` 的 `external_scan` 類別不變：只限已嘗試執行但失敗的掃描，須附 `attempted_command` 與 `failure_detail`。

### 標記 `review` 前的自檢（三題皆須通過）

1. 取得完整部署環境與營運文件後，結論是否可能改變？否 → 不得 `review`。
2. 所缺工件能否指名（檔名、平台、紀錄名稱）？不能 → 不得 `review`。
3. `decision_reason` 是否已出現缺陷、矛盾或不安全預設值？是 → 改 `fail`。

`review` 的 `decision_reason` 須以「待確認：」列出工件清單，並先寫已由程式碼判定的部分。預期 `review` 比例約 25% 以下；超過 40% 須逐條以上述自檢重審（驗證器於 70% 警示，不作為放行標準）。
