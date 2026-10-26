# 審查完整性守門與唯讀平行分工

完整性寫入由**單一主代理**負責。可選擇讓子代理並行進行唯讀原始碼分析，子代理不得呼叫 `--stage`、`--integrate`、修改 assessment 或作正式結案。70 項規則、逐檔 10 類篩選、來源覆蓋率、正式 assessment Schema 與 HTML／JSON 報告均維持原樣。Python 工具只準備工作與阻擋不一致資料，不自動判定 Pass／Fail。

## 作業順序

1. 原有環境檢查與 `analysis_prepare.py --target <TARGET_ROOT> --mode full` 執行一次，建立 `analysis/structure-index.json` 和 `analysis/review-snapshot.json`。
2. 執行 `review_safety.py --target <TARGET_ROOT> --plan`，取得**全部 70 項**的查核範圍。即使沒有來源命中，`project` 項目仍須查核控制責任、完整檔案清單及外部工件；不能因為找不到程式碼就直接 `na`。
3. 維持逐檔完整適用性篩選。 `typed_relationships` 額外提供 DI、設定引用、Endpoint 授權、Middleware 管線、跨專案引用及 Roslyn 方法候選。所有 `resolution=candidate_only`，即使 Roslyn 顯示語意符號匹配仍必須由 Agent 閱讀來源確認；反射、動態 DI、環境覆寫、外部 Proxy 等未被索引證實的路徑須主動追查。
4. 審查中先產生獨立批次 JSON，僅主代理透過 `--stage` 暫存、`--integrate` 整合。不能直接以暫存資料宣稱規則 completed，也不能以沒有衝突表示安全控制有效。子代理僅提供唯讀建議，由主代理親自核對來源、衝突與證據；預設亦可每檔／每批循序處理。
5. 對每條 `cross_file`／`project` 規則建立人工核對的 `closures`，記錄責任歸屬、全域搜尋、實際追查的來源、關聯候選與尚未關閉的補查任務；待任務都完成才可結案。 `local` 規則仍須依既有控制及來源證據確認全案適用性。
6. 執行 `review_safety.py --target <TARGET_ROOT> --validate`，然後由原有 `review_queue.py` 確認 `ready_for_report=true`，最後執行 `complete_review.py`。正式驗證器會拒絕來源版本不一致、缺少結案、以及來源異動後尚未重查的規則。

以上 Python 都是 Skill Agent 在受測專案中自行呼叫，不要求一般使用者手動操作。Windows 使用 `run-python.cmd` 包裝，Unix 使用 `run-python.sh`。

## 範圍類型與限制

- `local`：本檔控制或直接設定能提供主要證據；若實際存在跨檔依賴仍須追查。
- `cross_file`：需核對入口、實作、使用處、組態與可能繞過；若最終證明只有一檔，`single_file_justification` 必須具體說明排除其他必要關聯的方法。
- `project`：即使沒有任何關鍵字命中，也要執行全專案搜尋、確認責任層及是否有儲存庫外工件。

範圍為**最小審查責任**，不是控制安全性的自動判定。所有規則仍按 `policies/review-decision-matrix.json` 的 static／hybrid／external 判定；缺少測試不自動改成 review。具體缺陷仍須建 Finding。

## 批次暫存資料契約

Agent 可將既有完整格式的單檔審查結果、規則結論及 Findings 放在一個 JSON 物件：

```json
{
  "file_reviews": [],
  "checks": [],
  "findings": [],
  "closures": {
    "AC-01": {
      "status": "pass",
      "summary": "已追查所有登入入口、Session 發行與逾時驗證的完整控制鏈及可能繞過條件",
      "examined_paths": ["src/Web/Program.cs", "src/Identity/IdentityService.cs"],
      "control_owner": "身分驗證服務與 ASP.NET Core 驗證管線",
      "search_summary": "已查找 Cookie、JWT、Session、Redis 及其設定覆寫、驗證器和使用端；依實際專案結果逐一說明",
      "examined_relationship_ids": [],
      "open_issues": []
    }
  }
}
```

**上述只是結構示例，不能複製其中內容當成真實證據或 Pass 結論。** `examined_relationship_ids` 僅可引用 `analysis/structure-index.json` 中實際存在的 `typed_relationships[].id`；`open_issues` 非空時不得完成規則。若為 `cross_file` 且僅核對一份來源，需附至少 20 字的 `single_file_justification`。每份 `checks[]` 仍是原有正式 Schema 的完整單條規則物件，不是任意局部 patch。

```bash
python "<SKILL_ROOT>/scripts/review_safety.py" --target "<TARGET_ROOT>" --stage "<TARGET_ROOT>/reports/security-code-review/analysis/my-batch.json"
python "<SKILL_ROOT>/scripts/review_safety.py" --target "<TARGET_ROOT>" --integrate
python "<SKILL_ROOT>/scripts/review_safety.py" --target "<TARGET_ROOT>" --validate
```

- `--stage` 只寫 `analysis/staged/`，**不會更改**原本 `assessment.json`。
- `--integrate` 先檢查快照及資料衝突，再以原子替換保存 `assessment.json`，並保留所有既有 Findings。相同弱點的確切指紋去重；不同來源或不同描述不強行合併。
- 已完成規則、相同檔案或結案結果不同時會阻擋，先人工核對；確實要更新舊證據，可明確加 `--allow-revision`，但不能藉此把原有 `fail` 改成非 `fail`。
- 暫存的 `file_reviews` 在規則結案前可不符合正式 completed 雙向關聯；**正式交付時**仍必須完全通過既有 `file_review_integrity.py`，不可減少規則覆蓋或修改報告格式。
- `--integrate` 不代替 `validate_assessment.py`，不可憑整合成功宣稱 70/70。

## 跨檔呼叫點必須人工結案

新版 `analysis/structure-index.json`（`schema_version=3`）包含 `cross_file_call_hints` 的每筆 `id`、`resolution`、`candidate_count` 與 **完整** `possible_targets`，不再以固定前 8 個目標／前 200 個呼叫點切斷追查。

- `semantic_symbol_candidate`：Roslyn 合成編譯可解析到宣告，但仍不代表目標專案的實際建置或執行時繫結。
- `semantic_dispatch_candidate`：介面／虛擬呼叫，仍可能有 DI、動態分派等其他實作。
- `receiver_type_candidate`：接收者型別名稱限縮的候選。
- `name_only_ambiguous`：僅憑方法名稱／參數數量的多個候選，**不可直接確認**。
- `dispatch_requires_manual_search`：Roslyn 找到介面／虛擬宣告但沒有可定位的跨檔實作；保留未解呼叫點，Agent 必須自行查找註冊、覆寫、動態代理與外部實作。

- Roslyn／CodeGraph 不可用時，保留原始碼追查責任；索引無候選不等於無跨檔依賴。

新索引下，`cross_file`／`project` 規則要在原本 `closures` 中加入與規則實際相關的 `callsite_reviews`；只需追查真正相關的呼叫點，但不可把索引未覆蓋到的反射／Factory／動態代理當作已確認安全。

```json
{
  "callsite_reviews": {
    "<structure-index 中實際存在的呼叫點 ID>": {
      "status": "verified",
      "selected_targets": ["src/Services/ExampleService.cs"],
      "reason": "已閱讀呼叫端、方法宣告與 DI 註冊，核對目標實作、組態及其他可能的繞過路徑"
    }
  }
}
```

上述僅是**格式示意，禁止直接套用或捏造證據**。

`verified`：`selected_targets` 至少一個，且必須在 `examined_paths`，Agent 已驗證真正來源及呼叫鏈。`excluded`：沒有選取目標，必須說明確實不屬於該規則控制鏈的具體理由。`unresolved`／缺少紀錄：不得結案；先補查到足以確認或排除。機械驗證只能檢查紀錄可追溯性，不能證明 Agent 的語意判定一定正確。

對已存在的舊審查進度，保留原始 Finding 與證據；首次改用新版索引時應重新建立快照／依失效範圍查核，不得以新版候選覆寫舊有安全結論。

## 可驗證的跨檔控制鏈

新建的 `structure-index.json` 啟用 `cross_file_evidence_version=1`。對適用的跨檔規則，僅記錄 `examined_paths` 或勾選 `examined_relationship_ids` 已不足以結案：`closures[rule_id].control_trace` 必須以實際來源建立控制鏈。具有程式碼控制的全專案規則亦須提供控制鏈；完全屬部署／營運工件的控制不強制捏造 Controller 或 Repository。

`control_trace` 使用以下欄位，這是**資料契約示意，不能當作已查證來源**：

```json
{
  "boundary": "connected",
  "nodes": [
    {
      "role": "entry",
      "path": "src/Web/Controllers/OrdersController.cs",
      "line_start": 35,
      "line_end": 35,
      "reason": "說明實際的 HTTP 入口及從此入口如何呼叫授權處理"
    },
    {
      "role": "enforcement",
      "path": "src/Application/Services/OrderService.cs",
      "line_start": 81,
      "line_end": 81,
      "reason": "說明呼叫時採取的具體身分與資料歸屬控制條件"
    }
  ],
  "relationships": [
    {
      "relationship_id": "<typed_relationships 內真實存在的 ID>",
      "evidence": {
        "path": "src/Web/Controllers/OrdersController.cs",
        "line_start": 35,
        "line_end": 35
      },
      "reason": "已閱讀來源呼叫與實際接收端，確認此關聯屬於本條規則"
    }
  ]
}
```

- `nodes[].role` 支援 `entry`／`enforcement`／`operation`／`configuration`／`support`。來源路徑、行號必須存在於本次快照、`examined_paths` 及正式 `execution.inspected_paths`；至少一個節點需與本規則正式證據有交集。
- `boundary=connected`：至少兩個不同來源檔及一條**確認**的結構關聯；入口、控制、操作等核心節點需可連通。不要求每條規則都有 Controller→Handler→Service→Repository 四層，但真實存在的鏈不得任意截斷。
- `boundary=single_file`：控制實際只在一個來源檔時，節點只包含該檔，`relationships=[]`，並提供 `boundary_reason` 及原有 `single_file_justification`。禁止為了滿足結案條件虛構跨檔關聯。
- `relationships` 中每一筆確認的 ID 必須屬於索引、連結已讀節點，其 `evidence` 必須涵蓋索引的原始呼叫／註冊位置，且與 `examined_relationship_ids` 完全一致；`method_call_hint` 另需 `callsite_reviews` 中有對應 verified 目標。
- `callsite_reviews` 的每筆紀錄新增 `evidence` 指向**實際呼叫行**。verified 須有 `binding`（direct／interface_dispatch／dependency_injection／configuration／middleware／other_verified）；excluded 須有 `exclusion_basis`（unrelated_rule／different_entry／unrelated_symbol／not_invoked／alternative_implementation）及足以核對的來源與理由。
- `dismissed_relationships[edge_id]` 由原先自由文字，改為含 `basis`、`reason`、`evidence`（來源路徑與行號）的物件；沒有逐條證據不得大量排除。排除理由重複過度時會阻止結案，必須重新調查。
- 為避免掃描全案後每條規則都繼承無關候選，新版結案只使用本規則的搜尋候選路徑及 `control_trace.nodes` 作為候選錨點，**不再將整份 `examined_paths` 當作關聯擴散的依據**。來源覆蓋率的既有要求不因此放寬。

Python 僅驗證來源可定位、控制鏈一致與候選排除紀錄具體；即使所有檢查通過，仍不等同證明呼叫路徑的語意正確或不存在攻擊繞過。Agent 必須重新閱讀相關檔案並驗證控制行為。

**升級／重新審查：** 新結構索引採用新的版本，原有已完成判定及 Findings 不會自動刪除或轉換。對來源未變更但尚未補充控制鏈證據的既有完整審查，須依法核對資料完整性後修訂結案；發生 Git／來源異動則依 `--snapshot-refresh`、重建索引與重新檢核流程處理。舊結構索引不強制新欄位，亦不得聲稱具此功能。

## 來源變更及恢復

`review-snapshot.json` 固定 Git Revision、完整來源檔清單、SHA256 與排除範圍。即使程式碼新增、刪除、修改，或 Git Revision 改變，也不能以原有 completed 當作新版本符合性證據。

異動後先查明原因，使用：

```bash
python "<SKILL_ROOT>/scripts/review_safety.py" --target "<TARGET_ROOT>" --snapshot-refresh
python "<SKILL_ROOT>/scripts/analysis_prepare.py" --target "<TARGET_ROOT>" --mode full
```

刷新不清除原有 Findings、舊判定、file_reviews；會清除失效的結案與產生 `analysis/recheck-required.json`，要求原本 completed 的規則以真實證據重新審查。Agent 須藉由新的暫存 `checks[]` 覆核證據並重新整合，全部重查完畢才能正式交付。尚有暫存資料時不得刷新快照。若已存在相互矛盾的 findings／狀態，須人工裁決，不能以格式修補繞過。

現行啟發式仍無法證明所有執行時動態連結、所有語意資料流或程式碼確曾被閱讀；必須保留來源追查與審查者複核，不能視為完整 SAST。
