# 規避測試集結果

由 `python3 tests/evasion/report.py --markdown docs/EVASION.md` 產生，案例定義在 `tests/evasion/evasion_cases.py`，封包在 `tests/pcaps/evasion.pcap`。

一個案例的所有攻擊 sid 都觸發才算偵測到；正規化異常（雙重編碼等）由回歸測試另外驗證，不影響偵測率。`make test` 會在偵測率低於 95%、出現沒有記錄原因的漏報、或已記錄的漏報其實已被偵測到時失敗。

| 類別 | 案例數 | 偵測 | 偵測率 |
|---|---:|---:|---:|
| URL encoding | 27 | 27 | 100.0% |
| Mixed case | 15 | 15 | 100.0% |
| Path obfuscation | 24 | 24 | 100.0% |
| HTTP parameter pollution | 9 | 8 | 88.9% |
| **合計** | **75** | **74** | **98.7%** |

## 已知漏報

### HTTP parameter pollution：Split comment across query and body (ASP.NET Request.Params)

- 請求：`POST /submit?id=1%20UNION/*`，body `id=*/SELECT+1`
- 應觸發：900014
- 原因：重複參數只在 query 內或 form body 內各自計算，不會跨兩者合併。要合併必須把 query 參數保存在 transaction 狀態裡，等 body（可能晚很多個封包才到）到齊再比對。

