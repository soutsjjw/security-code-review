# Known-positive and known-negative .NET fixture

此測試專案刻意包含兩項有弱點的範例，以及兩項相對安全的對照。請**僅**用於本地 P3 品質試驗，不要用於正式服務。此資料集的標籤不構成對未知漏洞的客觀證明。

- `UnsafeOrderAccess.Load`：AC-08，未核對物件所有權。
- `UnsafeSessionValidator.Valid`：AC-01，未核對 Session 到期。
- `SafeOrderAccess.Load`：AC-08，依呼叫者所有權查詢。
- `SafeSessionValidator.Valid`：AC-01，拒絕過期 Session。

使用相同 Git 修訂、相同模型與執行器條件，分別由單代理、多代理對**此測試專案**執行正式審查，人工對照每個案例的真實 Finding，將結果紀錄成 `{"detected":["idor-unsafe"],"tokens":0,"elapsed_seconds":1,"tokens_measured":false}` 格式。再使用 `scripts/multi_agent_benchmark.py` 比較召回、誤報與耗時；Token 不可憑推估填報。`multi_agent_security_cases.json` 是事先固定的正反標籤，不是掃描結果。
