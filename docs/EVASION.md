# 規避測試集結果

由 `python3 tests/evasion/report.py --markdown docs/EVASION.md` 產生，案例定義在 `tests/evasion/evasion_cases.py`，封包在 `tests/pcaps/evasion.pcap`。

一個案例的所有攻擊 sid 都觸發才算偵測到；正規化異常（雙重編碼等）由回歸測試另外驗證，不影響偵測率。`make test` 會在偵測率低於 95%、出現沒有記錄原因的漏報、或已記錄的漏報其實已被偵測到時失敗。

| 類別 | 案例數 | 偵測 | 偵測率 |
|---|---:|---:|---:|
| URL encoding | 25 | 23 | 92.0% |
| Mixed case | 15 | 15 | 100.0% |
| Path obfuscation | 24 | 24 | 100.0% |
| HTTP parameter pollution | 9 | 8 | 88.9% |
| **合計** | **73** | **70** | **95.9%** |

## 已知漏報

### URL encoding：Encoded tab between UNION and SELECT

- 請求：`GET /?id=1%09UNION%09SELECT%091`
- 應觸發：2002
- 原因：規則 2002 比對的是字面字串 'UNION SELECT'，但 SQL 允許兩個關鍵字之間是任何空白字元（tab、換行）或行內註解。需要 Phase 4 的 PCRE2，例如 UNION[\s/*]+SELECT。

### URL encoding：Encoded newline between UNION and SELECT

- 請求：`GET /?id=1%0aUNION%0aSELECT%0a1`
- 應觸發：2002
- 原因：規則 2002 比對的是字面字串 'UNION SELECT'，但 SQL 允許兩個關鍵字之間是任何空白字元（tab、換行）或行內註解。需要 Phase 4 的 PCRE2，例如 UNION[\s/*]+SELECT。

### HTTP parameter pollution：Split comment across query and body (ASP.NET Request.Params)

- 請求：`POST /submit?id=1%20UNION/*`，body `id=*/SELECT+1`
- 應觸發：900014
- 原因：重複參數只在 query 內或 form body 內各自計算，不會跨兩者合併。要合併必須把 query 參數保存在 transaction 狀態裡，等 body（可能晚很多個封包才到）到齊再比對。

