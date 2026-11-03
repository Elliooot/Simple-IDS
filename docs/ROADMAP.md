# SimpleIDS 規格與發展計畫書

> 狀態：草案 v0.1（2026-11-03）
> 基準版本：commit `8dbe7c3`（Phase 1 完成）
> 進度：Phase 1.5 完成（分支 `phase-1.5`，2026-11-03）
> 用途：作為後續開發（含 Claude Code 雲端 session）的單一依據。每完成一項，就在對應的 checkbox 打勾，並註記 commit。

---

## 1. 現況摘要

SimpleIDS 是以 C + libpcap 撰寫的單執行緒、特徵比對式網路入侵偵測系統（NIDS）。

| 項目 | 現況 |
|---|---|
| 程式規模 | 約 860 行（C 約 700 行、規則 33 行、Python 測試 159 行） |
| 擷取 | `pcap_open_live`，BPF 過濾 `tcp port 80/443/8080` |
| 解碼 | Ethernet / DLT_NULL / Linux SLL → IPv4 → TCP（單一封包、不重組） |
| 偵測 | 類 Snort 規則，只支援 `content`、`nocase`、`msg`、`sid`、`priority`，以 `strstr` 逐條比對 |
| HTTPS | 從 TLS ClientHello 擷取 SNI，比對網域規則 |
| 異常偵測 | 每 IP 請求頻率、URL 長度、惡意 User-Agent |
| 輸出 | 終端機訊息 + JSON Lines log |
| 測試 | `tests/test_ids.py` 只送出請求，不驗證是否真的告警 |

---

## 2. Phase 1.5：已知缺陷（成熟化之前必須先修）

以下問題已在 2026-11-02 的審查中，用 AddressSanitizer 和測試 harness 實際重現。

### 記憶體安全（最優先）
- [x] **B1** `main.c:111`：payload 沒有 NUL 結尾，`strncmp`、`strstr`、`strcasestr_custom` 都會讀出界。正常封包就會觸發。（`f82c1d3`；測試：`b1_stale_buffer`、unit `bytes`/`engine`）
- [x] **B2** `main.c:112`：payload 長度用了 `header->len`，應改用 `header->caplen`；IP/TCP header 長度也沒跟 `caplen` 比對。（`f82c1d3`；測試：`b2_truncated`、`test_decode_every_prefix`）
- [x] **B3** `rules.c:58`：`sscanf("%s …")` 沒限制寬度，`action[16]`、`protocol[8]`、`options[256]` 都可能溢位。（`f82c1d3`；測試：`test_parse_overlong_*`）

### 偵測邏輯
- [x] **B4** 規則沒有 `content`，或內容長度 ≥ 256 時，content 為空字串，會比對到所有封包。（`f82c1d3`；測試：`test_parse_requires_content`）
- [x] **B5** 規則 parser 不處理跳脫字元，所以 sid 4002、4004 這兩條反斜線規則永遠不會觸發。（`f82c1d3`；另支援 `|hex|`；測試：`test_parse_escapes`、`http_signatures`）
- [x] **B6** 沒檢查 IP 版本和 address family / ethertype，IPv6 會被當成 IPv4 解析，結果完全漏報。（`f82c1d3`：非 IPv4 一律計數後略過；真正解碼 IPv6 屬於 Phase 2。測試：`b6_non_ipv4`）
- [x] **B7** `match_packet` 不回傳 sid，所以 log 裡的 sid 一律是 0。（`f82c1d3`；每條命中規則各寫一筆 alert）
- [x] **B8** 頻率限制的 IP 表沒有淘汰機制，裝滿 1024 筆之後，新的 IP 就不會再被偵測。（`f82c1d3`：LRU 淘汰；測試：`b8_rate_table_full`）
- [x] **B9** `rules.c` 的 `tolower(char)` 沒先轉成 `unsigned char`，是未定義行為。（`f82c1d3`；測試：`test_find_nocase_high_bytes`）

### 輸出與環境
- [x] **B10** JSON log 沒跳脫 `msg` 和控制字元，輸出不是合法的 JSON。（`f82c1d3`；測試：`b10_json_escape`，回歸測試會驗證每一行都是合法 JSON）
- [x] **B11** log 路徑 `../logs/ids.log` 是相對於執行時的目錄，開檔失敗也沒處理。（`f82c1d3`：`-l` 可設定，預設 `logs/ids.log`，開檔失敗直接結束）
- [x] **B12** macOS 的預設介面應該是 `lo0`，不是 `lo`。（`f82c1d3`）
- [x] **B13** `main.c:93` 把 `packet + 14` 直接 cast 成 `struct ip *`，是未對齊存取（UB），應改用 `memcpy`。（`f82c1d3`：改為逐位元組讀取；測試：`test_decode_unaligned_buffer`）
- [x] **B14** `anomaly.c:75` printf 錯字，`\n` 位置也放錯。（`f82c1d3`：異常改成正式 alert，sid 9000xx）
- [x] **B15** repo 追蹤了編譯產物（`SimpleIDS`、`src/SimpleIDS`、`src/sniffer`、`tests/__pycache__`），應移除並加進 `.gitignore`。（`a4693b2`；CI hygiene job 會檢查）
- [x] **B16** 測試不會驗證結果，應改成讀 JSON log 來判斷是否告警。（`c8665a1`：`tests/live/test_live.py`）

**驗收條件**：開啟 `-fsanitize=address,undefined` 後，所有回歸測試都通過；B1–B16 每一項都至少有一個對應的測試案例。

---

## 3. 成熟化目標

### 3.1 願景
做一個**可讀、可測、可信任**的教學級 NIDS。它應該能離線分析 pcap，也能即時監聽；規則語言要是 Suricata/Snort 的實用子集；面對惡意流量不會崩潰；結果要能用測試證明。

### 3.2 非目標（明確不做）
- 不追求完整相容 Snort 或 Suricata 的規則語法。
- 不追求 10 Gbps 線速，也不做 DPDK、PF_RING 這類 kernel bypass。
- 不支援 Windows（只支援 Linux 和 macOS）。
- 預設不做 IPS 的封包阻擋，只在 Phase 6 列為選配項目。

### 3.3 品質目標（成熟版的 Definition of Done）
| 面向 | 指標 |
|---|---|
| 正確性 | pcap 回歸測試的偵測率 100%，正常流量的誤報為 0 |
| 穩健性 | 每個 parser 都 fuzz 過 ≥ 24 小時，沒有任何 sanitizer 錯誤 |
| 效能 | 單執行緒處理 HTTP 混合流量 ≥ 500 Mbps（離線 pcap、Apple Silicon 或同級 x86） |
| 記憶體 | 有固定上限，可設定（例如 flow table 和重組 buffer 合計 ≤ 256 MB） |
| 可維運 | 設定檔、規則熱重載（SIGHUP）、統計輸出、降權執行 |
| 建置 | Linux 和 macOS 的 CI 都通過，用 `-Wall -Wextra -Werror` 編譯 |

---

## 4. 目標架構

```
 ┌────────────┐   ┌──────────┐   ┌────────────┐   ┌──────────────┐
 │ Capture    │──▶│ Decoder  │──▶│ Flow Table │──▶│ TCP Stream   │
 │ live / pcap│   │ L2/L3/L4 │   │ 5-tuple    │   │ Reassembly   │
 └────────────┘   └──────────┘   └────────────┘   └──────┬───────┘
                                                         ▼
 ┌────────────┐   ┌──────────────────────┐   ┌──────────────────┐
 │ Output     │◀──│ Detection Engine     │◀──│ App-layer Parser │
 │ EVE JSON   │   │ MPM prefilter (AC)   │   │ HTTP / TLS / DNS │
 │ syslog/stat│   │ + rule eval + anomaly│   │ + normalization  │
 └────────────┘   └──────────────────────┘   └──────────────────┘
```

### 4.1 模組規格

| 模組 | 職責 | 關鍵設計 |
|---|---|---|
| `capture/` | 即時擷取，或離線讀取 pcap（`-r file.pcap`） | 離線模式讓測試和 CI 不需要 root |
| `decode/` | Ethernet、VLAN、DLT_NULL、SLL、IPv4、IPv6、TCP、UDP | 每一層都用 `caplen` 檢查邊界，欄位用 `memcpy` 讀出，避免未對齊存取 |
| `flow/` | 以 5-tuple 為鍵的 hash table，追蹤雙向連線狀態 | 有逾時和 LRU 淘汰，數量有上限；hash 加隨機種子，防止碰撞 DoS |
| `stream/` | TCP 重組：處理亂序、重送、重疊 | 重疊時的處理策略要可設定（first 或 last），因為重疊是常見的 IDS 規避手法；每條 flow 有 depth 上限 |
| `app/http` | 解析 HTTP/1.x 請求和回應 | URL decode、`%u` 和 double encoding、路徑正規化（`/./`、`//`、`..`）、header 解析、chunked body |
| `app/tls` | 解析 ClientHello 和 ServerHello | SNI、ALPN、JA3、JA4 指紋；能辨識 ECH（ECH 會把 SNI 加密） |
| `app/dns` | 解析 DNS 查詢和回應（UDP 53） | 網域黑名單、DGA 熵值啟發式、tunneling 長度異常 |
| `detect/` | 規則引擎 | 先用 Aho-Corasick 多樣式比對篩選候選規則，再逐條完整驗證規則 |
| `anomaly/` | 統計式異常偵測 | 滑動視窗計數、port scan 偵測、SYN flood；所有表格都有上限，並有淘汰機制 |
| `output/` | EVE 風格的 JSON、syslog、統計資訊 | 處理 log 輪替，用正確的 JSON 跳脫，告警事件和 flow 事件分開輸出 |
| `core/` | 設定檔、CLI、訊號處理、降權 | 處理 SIGHUP（重載規則）、SIGINT（輸出統計後結束）；開啟裝置後降權成非 root |

### 4.2 規則語言（Suricata 實用子集）

```
alert http any any -> $HOME_NET any (
    msg:"SQLi UNION in URI"; flow:to_server,established;
    http.uri; content:"union"; nocase; content:"select"; distance:0; within:20;
    pcre:"/union\s+(all\s+)?select/i";
    classtype:web-application-attack; sid:2002; rev:2; priority:1;
)
```

| 類別 | 支援項目 |
|---|---|
| 標頭 | `alert`、`drop`（Phase 6 才用）、`pass`；協定：`tcp`、`udp`、`http`、`tls`、`dns`；IP/port 變數（例如 `$HOME_NET`）、清單、否定 |
| 內容比對 | 可多個 `content`、`nocase`、`offset`、`depth`、`distance`、`within`；十六進位寫法 `\|3C 73\|`；否定 `!` |
| 比對緩衝區 | `http.uri`、`http.method`、`http.header`、`http.user_agent`、`http.request_body`、`tls.sni`、`ja3.hash`、`dns.query` |
| 進階 | `pcre`（PCRE2，有逾時上限）、`flow`、`threshold`、`detection_filter` |
| 中繼資料 | `msg`、`sid`、`rev`、`classtype`、`priority`、`reference`、`metadata` |
| 工具 | `simpleids --test-rules` 檢查規則語法、偵測重複 sid、警告效能較差的規則 |

---

## 5. 分階段里程碑

每個 Phase 都要有可以獨立展示的成果，並附上驗收條件。

### Phase 1.5 — 修正與測試地基
- [x] 修完 B1–B16（`a4693b2`、`f82c1d3`、`c8665a1`）
- [x] 支援離線讀檔 `-r file.pcap`（後面所有測試的基礎）（`f82c1d3`）
- [x] 建立 C 單元測試框架，選一個輕量的，例如 [greatest](https://github.com/silentbicycle/greatest) 或自寫的 assert 巨集（`c8665a1`：自寫，`tests/unit/test.h`）
- [x] 建立 pcap 回歸測試：`tests/pcaps/*.pcap` 搭配 `*.expected.json`，用 `make test` 比對告警結果（`c8665a1`：`tests/regression/`）
- [x] GitHub Actions CI：Ubuntu 和 macOS 兩個平台，跑一般建置和 ASan/UBSan 兩種建置（`a2ee01f`）
- [x] 調整目錄結構，改成 §8 的規劃（`f82c1d3`：現有模組已搬移；`flow/`、`stream/`、`app/dns/`、`tests/fuzz/`、`etc/` 等留給對應的 Phase 建立）
- **驗收**：`make test` 全部通過，CI 是綠燈。

### Phase 2 — 解碼與連線追蹤
- [ ] 支援 IPv6、VLAN 和 UDP 解碼
- [ ] Flow table：雙向、有逾時、有上限、hash 加隨機種子
- [ ] TCP 重組，可設定重疊時的處理策略
- [ ] 能偵測攻擊字串跨封包、亂序送達的情況
- **驗收**：準備一份 pcap，把 `<script>` 拆成 3 個亂序封包，仍然要偵測到；送 100 萬條 flow，記憶體要維持在上限內。

### Phase 3 — 應用層與正規化
- [ ] HTTP parser 和正規化，提供 `http.*` 比對緩衝區
- [ ] TLS：SNI、ALPN、JA3、JA4，並辨識 ECH
- [ ] DNS parser 和網域規則
- [ ] 規避測試集：URL encoding、大小寫混用、路徑混淆、HTTP 參數污染
- **驗收**：規避測試集的偵測率 ≥ 95%，每一個漏報都要寫明原因並記錄下來。

### Phase 4 — 偵測引擎強化
- [ ] 實作規則語言 v2（§4.2 的內容）
- [ ] 用 Aho-Corasick 做 MPM 預篩，搭配 PCRE2
- [ ] 實作 `threshold` 和 `detection_filter`，避免告警洪水
- [ ] 規則熱重載（SIGHUP），重載過程要原子化
- [ ] 實作 `--test-rules` 規則檢查工具
- [ ] 擴充規則庫到 150–300 條，參考 OWASP CRS 的分類
- **驗收**：載入 300 條規則時，吞吐量下降 < 30%（跟 10 條規則比較）。

### Phase 5 — 穩健性與維運
- [ ] 用 libFuzzer 為 decoder、HTTP、TLS、DNS、規則 parser 各寫一個 fuzz target，並放進 CI 跑短時間的 smoke 測試
- [ ] 降權：開啟裝置後 `setuid`/`setgid`；Linux 加上 seccomp，macOS 研究 sandbox
- [ ] 編譯強化：`-D_FORTIFY_SOURCE=3`、`-fstack-protector-strong`、PIE、RELRO
- [ ] 設定檔（INI 或 YAML 子集），並支援 log 輪替
- [ ] 統計輸出：pps、丟包率、flow 數、記憶體用量
- [ ] 效能基準測試：`make bench` 跑固定的 pcap，輸出 Mbps
- **驗收**：每個 fuzz target 累積 ≥ 24 小時沒有 crash，達到 §3.3 的效能目標。

### Phase 6 — 進階選配（依興趣挑選）
- [ ] **多執行緒**：依 flow hash 把封包分給多個 worker，每個 worker 有自己的 flow table
- [ ] **IPS 模式**：Linux 用 NFQUEUE 做 inline 阻擋，讓 `drop` 規則真正生效
- [ ] **QUIC Initial 解密**：從 QUIC Initial 封包取出 SNI。Initial 的金鑰是由公開的 salt 和連線 ID 推導出來的（RFC 9001），可以順便練習密碼學
- [ ] **加密流量分析**：在不解密的情況下，用封包長度、時間間隔、JA4 做分類（偏機器學習）
- [ ] **Web 儀表板**：讀取 EVE JSON 做視覺化
- [ ] **規則轉換器**：把 Suricata 規則轉成 SimpleIDS 支援的子集，不支援的部分要回報

---

## 6. 測試策略

| 層級 | 工具 | 涵蓋範圍 |
|---|---|---|
| 單元測試 | C 測試框架 | 各 parser、規則 parser、Aho-Corasick、URL decode、JSON 跳脫 |
| 回歸測試 | pcap 搭配 expected JSON | 端到端偵測結果，每修一個 bug 就加一份 pcap |
| 規避測試 | 自製 pcap（用 Scapy 產生） | 分段、重疊、編碼、大小寫 |
| Fuzz | libFuzzer + ASan | 所有會處理外部輸入的 parser |
| 效能 | `make bench` | 吞吐量、每封包延遲、記憶體高峰 |
| 即時冒煙測試 | `tests/test_ids.py`（改寫版） | 在 lo/lo0 上實際收發，並讀 log 驗證結果 |

**原則**：不能用離線 pcap 重現的偵測行為，就當作還沒被測試。

---

## 7. 安全設計原則
1. 所有外部輸入（封包、規則檔、設定檔）都視為惡意。
2. 解析一律帶長度參數（`const uint8_t *buf, size_t len`），不依賴 NUL 結尾。
3. 所有表格和 buffer 都要有上限和淘汰機制，記憶體不能被攻擊者撐爆。
4. hash 加隨機種子，PCRE 設逾時上限，防止 algorithmic complexity DoS。
5. 開啟擷取裝置之後立刻降權。
6. 任何解析錯誤都只丟掉該封包並計數，不能讓整個程式終止。

---

## 8. 目標目錄結構

```
Simple-IDS/
├── CLAUDE.md               # 給 Claude Code 的專案說明
├── Makefile                # all / test / asan / fuzz / bench / clean
├── docs/ROADMAP.md         # 本文件
├── etc/simpleids.conf
├── rules/{http,tls,dns,scan}.rules
├── include/simpleids/*.h
├── src/
│   ├── core/  capture/  decode/  flow/  stream/
│   ├── app/{http,tls,dns}/  detect/  anomaly/  output/
│   └── util/              # hash、ring buffer、memory pool、JSON writer
├── tests/
│   ├── unit/  pcaps/  evasion/  live/
│   └── fuzz/
└── .github/workflows/ci.yml
```

---

## 9. 成品規模估算

以完成 Phase 1.5–5 計算，不含 Phase 6 選配。

| 模組 | 預估 C 程式行數 |
|---|---:|
| capture + core（CLI、設定、訊號、降權） | 600 |
| decode（L2/L3/L4、IPv4/IPv6） | 600 |
| flow table | 450 |
| TCP 重組 | 900 |
| HTTP parser 與正規化 | 800 |
| TLS（SNI、ALPN、JA3、JA4） | 450 |
| DNS | 350 |
| 規則 parser（v2 語言） | 1,000 |
| 偵測引擎 + Aho-Corasick + PCRE2 整合 | 1,000 |
| anomaly | 450 |
| output（EVE JSON、syslog、統計） | 500 |
| util | 500 |
| 標頭檔 | 800 |
| **產品程式碼小計** | **約 8,400 行** |
| 單元測試 + fuzz targets | 2,500–3,000 |
| 測試工具（Python/Scapy 產生 pcap、回歸測試執行器） | 600–800 |
| 規則 | 150–300 條 |
| **合計** | **約 1.1–1.3 萬行** |

其他量化指標：
- **執行檔**：約 200–400 KB（動態連結 libpcap 和 PCRE2）。
- **測試資料**：50–100 個 pcap，總共約 5–20 MB。
- **跟現在比**：大約是 Phase 1 的 12–15 倍。
- **跟業界比**：Suricata、Snort 3 是數十萬行等級的專案。SimpleIDS 的定位是能讀完、能看懂的教學和研究用 NIDS，規模大約是它們的 2–5%，但涵蓋相同的核心概念（重組、正規化、MPM、規避防禦）。

時程粗估（一個人、業餘時間、搭配 Claude Code 開發）：

| Phase | 預估時間 |
|---|---|
| 1.5 | 1–2 週 |
| 2 | 3–4 週（TCP 重組最花時間） |
| 3 | 3–4 週 |
| 4 | 3–4 週 |
| 5 | 2–3 週 |
| **合計** | **約 3–4 個月** |

---

## 10. 參考資料
- Suricata 文件：規則格式、EVE JSON 格式（docs.suricata.io）
- Ptacek & Newsham, *Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection*（1998）：TCP 重組和規避攻擊的經典論文
- Aho & Corasick,（1975）*Efficient String Matching*
- RFC 9293（TCP）、RFC 9112（HTTP/1.1）、RFC 8446（TLS 1.3）、RFC 9001（QUIC-TLS）
- JA4+ 指紋規格（FoxIO）
- OWASP Core Rule Set：規則分類參考
