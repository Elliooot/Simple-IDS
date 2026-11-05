# SimpleIDS 規格與發展計畫書

> 狀態：草案 v0.1（2026-11-03）
> 基準版本：commit `8dbe7c3`（Phase 1 完成）
> 進度：Phase 5 完成（分支 `phase-5`，2026-11-05；24 小時 fuzz 驗收由 nightly workflow 累積中）；Phase 4 完成（分支 `phase-4`，2026-11-04）；Phase 3 完成（分支 `phase-3`，2026-11-03）；Phase 2 完成（分支 `phase-2`）；Phase 1.5 完成（分支 `phase-1.5`）
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
- [x] 調整目錄結構，改成 §8 的規劃（`f82c1d3`：現有模組已搬移；`flow/`、`stream/`、`app/dns/`、`tests/fuzz/`、`etc/` 等留給對應的 Phase 建立；`flow/`、`stream/` 已在 Phase 2 建立）
- **驗收**：`make test` 全部通過，CI 是綠燈。

### Phase 2 — 解碼與連線追蹤
- [x] 支援 IPv6、VLAN 和 UDP 解碼（`8e1a84a`：IPv6 擴充標頭 0/43/60/51/44，非首片段計數後略過；802.1Q/802.1ad 最多 2 層；UDP 長度檢查。測試：`test_decode_ipv6_*`、`test_decode_vlan`、`test_decode_udp`、回歸 `ipv6`、`vlan`）
- [x] Flow table：雙向、有逾時、有上限、hash 加隨機種子（`8e1a84a`：`src/flow/`，固定大小 pool + LRU 淘汰，逾時依 TCP 狀態而定，SipHash-2-4 + `/dev/urandom` 金鑰；`--max-flows`。測試：unit `flow`、回歸 `flow_eviction`）
- [x] TCP 重組，可設定重疊時的處理策略（`8e1a84a`：`src/stream/`，`--overlap first|last` 只作用於尚未交付的位元組，已交付的永不改寫；重疊內容不一致時發 sid 900005；`--stream-depth`、`--stream-memcap`。測試：unit `stream`、回歸 `stream_overlap_first/last`、`stream_retransmit`、`stream_gap`）
- [x] 能偵測攻擊字串跨封包、亂序送達的情況（`8e1a84a`：規則改在重組後的串流上比對，並處理 seq 繞回。測試：`test_engine_split_out_of_order`（6 種順序）、`test_engine_seq_wraparound`、回歸 `stream_split_ooo`）
- **驗收**：準備一份 pcap，把 `<script>` 拆成 3 個亂序封包，仍然要偵測到；送 100 萬條 flow，記憶體要維持在上限內。
  - ✅ `tests/pcaps/stream_split_ooo.pcap` 偵測到；`test_engine_million_flows_bounded` 送 100 萬條 flow（`--max-flows 4096`、memcap 1 MiB），flow 數與重組記憶體峰值都不超過上限，且確實觸發 memcap 丟棄。
- **行為說明與已知限制**
  - 只重組 client → server 方向（目前所有規則都檢查請求端）；回應方向只做 flow 狀態追蹤。
  - 告警以 flow 為單位去重：同一條 flow 內同一個 sid 只告警一次（重傳、重掃不會重複告警）。
  - 串流有洞時會等待補齊，直到 flow 結束（逾時、淘汰、關閉）才跳過；被 snaplen 截掉的位元組視為永久遺失，立刻跳過。比對不會跨越洞。
  - 預設 BPF filter 也涵蓋 VLAN 標籤內的流量，但 libpcap 的 `tcp port N` 看不到 IPv6 擴充標頭後面的 TCP；需要時請用 `-f ''` 關閉 filter。
  - 不做 IP 片段重組（IPv4/IPv6 的非首片段直接略過），留給 Phase 5 的規避防護。

### Phase 3 — 應用層與正規化
- [x] HTTP parser 和正規化，提供 `http.*` 比對緩衝區（`0a0baaf`：`src/app/http/`。緩衝區 `http.method`、`http.uri`（正規化後）、`http.uri.raw`、`http.header`、`http.user_agent`、`http.host`、`http.cookie`、`http.request_body`；規則可用 `startswith`、`endswith`、`dotprefix`。URI 正規化：absolute-form 去掉 scheme/host、percent-decode 最多 3 輪、`%u`（含全形字元）、overlong UTF-8、`\` 轉 `/`、`//`、`/./`、`..`；query 只解碼不做路徑正規化。Body：Content-Length、chunked、form 解碼。正規化異常 sid 900010–900015。測試：unit `httpnorm`、`test_engine_http_bodies`、回歸 `http_bodies`）
- [x] TLS：SNI、ALPN、JA3、JA4，並辨識 ECH（`0a0baaf`：ClientHello 可跨多個 TLS record 與 TCP 區段；GREASE 排除；MD5/SHA-256 在 `src/util/digest.c`；ECH（extension `0xfe0d`）發 sid 900030（資訊性）。緩衝區 `tls.sni`、`tls.alpn`、`ja3.hash`、`ja3.string`、`ja4.hash`。測試：unit `test_tls_fingerprints`、`test_tls_ech`；回歸 `tls_fingerprint` 的 JA3/JA4 由 `gen_pcaps.py` 以 Python 獨立計算，交叉驗證 C 實作）
- [x] DNS parser 和網域規則（`0a0baaf`：`src/app/dns/`，UDP 53 與 TCP 53（長度前綴，可跨區段）；跟隨壓縮指標（最多 16 跳）；`rules/dns.rules` 用 `dns.query; dotprefix; ... endswith` 比對網域與所有子網域；名稱 > 100 或 label > 50 發 sid 900020。測試：unit `dns`、`test_engine_dns`、回歸 `dns`）
- [x] 規避測試集：URL encoding、大小寫混用、路徑混淆、HTTP 參數污染（`f196c5a`：`tests/evasion/`，73 個案例，`make test` 會跑 `report.py`；結果與漏報原因見 [`docs/EVASION.md`](EVASION.md)）
- **驗收**：規避測試集的偵測率 ≥ 95%，每一個漏報都要寫明原因並記錄下來。
  - ✅ 70/73（95.9%）：URL encoding 23/25、大小寫 15/15、路徑 24/24、HPP 8/9。3 個漏報（`UNION%09SELECT`、`UNION%0aSELECT` 需要 Phase 4 的 PCRE2；query 與 body 間的 HPP 需要跨 body 的 transaction 狀態）已記錄在 `docs/EVASION.md`，`report.py` 會在出現未記錄的漏報時失敗。
- **行為說明與已知限制**
  - 應用層協定改由內容判斷（`16 03` → TLS、HTTP method → HTTP、port 53 → DNS），不再只看 port，所以 443 上的明文 HTTP、8888 上的 HTTP 都會用 HTTP 規則檢查。無法辨識、也沒有對應 raw `tcp` 規則的串流會立刻停止重組。
  - `rules/http.rules` 全部改用 sticky buffer：原本比對整個封包的規則拆成 `http.uri`／`http.header`／`http.request_body` 各自的版本（新增 1011、1012、2011、2012、3011；4004 改成 nocase；新增 4005 比對正規化後的 `/Windows/System32/`）。`..` 在路徑裡會被正規化消掉，所以 4001/4002 只會在 query 觸發，爬出根目錄則改由 900010 告警。
  - 串流有洞時，洞之前的不完整請求會先檢查，之後 HTTP parser 從下一個 request line 重新同步。
  - 正規化異常（900010–900015）和其他告警一樣以 flow 為單位去重。
  - 尚未實作：HTTP 回應解析、TLS ServerHello（JA3S/JA4S）、DNS 回應檢查、DGA 熵值啟發式。

### Phase 4 — 偵測引擎強化
- [x] 實作規則語言 v2（§4.2 的內容）（`4dd728f`：`src/detect/rule_parse.c`。動作 `alert`／`drop`／`pass`；協定 `ip`／`tcp`／`udp`／`http`／`tls`／`dns`；位址與 port 支援清單、否定、CIDR（v4/v6）、範圍 `lo:hi`、`$變數`（規則檔內的 `var`／`ipvar`／`portvar`、`--var NAME=VALUE`、內建預設值）、雙向 `<>`；每條規則最多 16 個 content／pcre 條件，可混用多個 sticky buffer，修飾詞 `nocase`、`offset`、`depth`、`distance`、`within`、`startswith`、`endswith`、`fast_pattern`、否定 `!`；`flow`、`classtype`（決定預設 priority）、`rev`、`reference`、`metadata`；規則檔可用 `\` 續行。測試：unit `rules`（35 個）、回歸 `rules_v2`）
- [x] 用 Aho-Corasick 做 MPM 預篩，搭配 PCRE2（`4dd728f`：`src/detect/mpm.c`，每個 (phase, buffer) 一個 DFA，字母表先轉小寫再壓縮；每條規則取一個 fast pattern（`fast_pattern` 指定，否則最長的正向 content），沒有 content 的規則放進每次都驗證的清單。相對比對依 Suricata 語意並可回溯（每次評估上限 4096 步）。PCRE2 啟用 JIT，match limit 10000、depth limit 2000，超過上限視為不符合並計數。測試：`test_mpm_classic`、`test_mpm_vs_naive`（隨機比對樸素搜尋）、`test_eval_prefilter_consistent`）
- [x] 實作 `threshold` 和 `detection_filter`，避免告警洪水（`4dd728f`：`src/detect/threshold.c`，`limit`／`threshold`／`both`／`detection_filter`，`track by_src`／`by_dst`／`by_rule`／`by_both`，固定大小的表格加 LRU 淘汰，時間用封包時間。測試：unit `threshold`、`test_engine_detection_filter`、`test_engine_threshold_limit`、回歸 `rules_v2`）
- [x] 規則熱重載（SIGHUP），重載過程要原子化（`4dd728f`、`7158c59`：先完整建好新規則集，零錯誤才一次換上；任何一行錯誤或檔案不見都保留舊規則並印出原因。訊號只設旗標並 `pcap_breakloop`，在兩個封包之間換。測試：`tests/cli/test_cli.py` 用 FIFO 餵封包，精確控制 SIGHUP 前後送達的封包）
- [x] 實作 `--test-rules` 規則檢查工具（`4dd728f`、`7158c59`：回報 `檔案:行號` 錯誤與重複 sid，警告效能較差的規則（沒有 fast pattern、fast pattern < 3 bytes、raw 規則不限 port、沒有 anchor 的 pcre 等），列出每個 phase 的規則數、預篩 pattern 數、DFA 狀態數與記憶體；有錯誤時 exit 1。測試：`tests/cli/test_cli.py`、`test_lint`）
- [x] 擴充規則庫到 150–300 條，參考 OWASP CRS 的分類（`4e16ece`：`rules/crs/` 共 267 條，加上核心 33 條共 300 條。分類對應 CRS 規則檔：913 掃描器、920／921 協定、930 LFI、931 RFI、932 RCE、933 PHP、934 通用（SSTI、Node.js、原型污染、SSRF、XXE、OAST）、941 XSS、942 SQLi／NoSQLi／LDAPi、943 session fixation、944 Java；sid 前三碼是 CRS 檔案編號，但規則內容是自己寫的，不是 CRS 的翻譯。每條都有 3 bytes 以上的 content anchor，`--test-rules` 零警告。測試：`tests/rules/test_library.py` 每條規則一個樣本必須觸發，另有 70 個正常請求必須零告警）
- **驗收**：載入 300 條規則時，吞吐量下降 < 30%（跟 10 條規則比較）。
  - ✅ `make bench`（`fd80ddd`）：40,000 個 HTTP 請求（完整 TCP 連線、瀏覽器 header、15% 表單 POST、2% 攻擊），10 條規則 578 Mbit/s、300 條規則 529 Mbit/s，下降 **8.5%**（雲端 Linux x86 容器，release 建置，5 次取最快）。同樣流量去掉攻擊後，300 條規則零告警。
- **行為說明與已知限制**
  - 告警語意改變：HTTP／TLS／DNS 這類解析過的訊息改成「每個訊息（transaction）各自告警」，跟 Suricata 一致；keep-alive 連線上兩個帶 `<script>` 的請求會有兩筆告警。raw 串流規則和異常偵測維持每條 flow 每個 sid 一次；raw UDP 規則每個 client→server 封包各自比對。一個 DNS 訊息裡多個 question 命中同一條規則只告警一次。
  - `pass` 規則命中後，該 flow 之後不再做任何規則比對（異常偵測照常）。`drop` 目前等同 `alert`（IPS 模式在 Phase 6）。
  - `flow:established`：TCP 除了 SYN_SENT 以外都算（含中途加入的連線）；UDP 在 server 回過封包之後才算。`flow:to_client` 永遠不會成立（目前只檢查請求方向）。
  - raw TCP 規則的重掃範圍：如果所有 raw TCP 規則都是單一正向 content，只重掃最長 content 長度的重疊區；否則每次從串流開頭重掃。
  - `http.header` 是正規化過的（`Name: value`，冒號前後空白去掉、折行合併），所以「冒號前多一個空白」這類 header 混淆無法直接比對；改由 921001（同時有 Content-Length 和 Transfer-Encoding）等規則抓。
  - 預設規則改成 `rules/*.rules` 加 `rules/crs/*.rules`；`-R` 可以指定目錄。pcap 回歸測試與規避測試固定只載入核心規則（`-R rules`），規則庫另有自己的測試，所以改規則庫不會影響引擎的回歸預期。
  - 核心規則 2002／2012 改用 PCRE2，Phase 3 的兩個 UNION 漏報已解決，規避測試集新增 2 個案例，偵測率 74/75（98.7%）。HPP 拆開註解的案例現在也會直接觸發 2002／2012（合併前的 `UNION/*&id=*/SELECT` 本身就是 UNION、註解、SELECT）。
  - WebDAV method（`PROPFIND`、`MKCOL` 等）現在也會被辨識成 HTTP。
  - JSON log 的 `proto` 原本固定寫 `TCP`，現在依實際協定輸出；`alert` 物件多了 `action`、`rev`、`category`。

### Phase 5 — 穩健性與維運
- [x] 用 libFuzzer 為 decoder、HTTP、TLS、DNS、規則 parser 各寫一個 fuzz target，並放進 CI 跑短時間的 smoke 測試（`535d1c1`：`tests/fuzz/` 共 7 個 target：`decode`（所有 link type）、`http`、`tls`、`dns`、`rules`（解析 → 編譯 → lint → 用輸入本身評估每個 buffer）、`engine`（多個 frame 走完整條 pipeline，含重組與 flow 淘汰）、`config`。`make fuzz`（clang + libFuzzer + ASan/UBSan，`FUZZ_TIME`／`FUZZ_JOBS`）；`make fuzz-replay` 用一般編譯器重播種子與 `tests/fuzz/regressions/`，是 `make test` 的一部分；種子由 `make_seeds.py` 從回歸 pcap、規則庫樣本、規則檔、設定檔產生，另有 HTTP／規則／設定的字典。CI 的 `fuzz-smoke` job 每個 target 跑 45 秒，`.github/workflows/fuzz.yml` 每晚每個 target 跑 3 小時並累計 CPU 時數、保存 corpus。**fuzz 找到一個真的 bug**：`http_check_params` 在參數名稱超過 `HPP_NAME_MAX` 時越界讀取（`55de180`，unit `test_hpp_long_name`、`regressions/http/hpp-long-name`））
- [x] 降權：開啟裝置後 `setuid`/`setgid`；Linux 加上 seccomp，macOS 研究 sandbox（`535d1c1`、`864549d`：`-u USER`／`-g GROUP`（或設定檔 `security.user`／`group`），在開好擷取裝置、BPF、log、規則與引擎之後才 `setgroups` → `setgid` → `setuid`，並確認 `setuid(0)` 會失敗；log 檔會先 `fchown` 給新使用者。接著進入 sandbox（`--no-sandbox` 或 `security.sandbox = no` 關閉）：Linux 是手寫的 seccomp-BPF allowlist（56 個 syscall，檢查 arch、擋 x32，`ioctl` 只允許 `TCGETS`，不允許 socket／exec／fork／ptrace），`PR_SET_NO_NEW_PRIVS`，違規時 `SECCOMP_RET_TRAP` 並印出 syscall 編號後以 159 結束；macOS 用 `sandbox_init` 的 SBPL profile 禁止網路、exec 與 fork（檔案系統仍可讀寫，因為 SIGHUP 要重讀規則、log 要輪替）。測試：unit `sandbox`（fork 子程序驗證 `socket()`／`exec` 被殺、檔案 I/O 與 rename 正常）、`priv_resolve`／`priv_drop`；以 nobody 實際監聽 `lo` 做過 live 測試）
- [x] 編譯強化：`-D_FORTIFY_SOURCE=3`、`-fstack-protector-strong`、PIE、RELRO（`535d1c1`：另外有編譯器支援時加 `-fstack-clash-protection`、`-fcf-protection=full`；Linux 連結 `-pie -z relro -z now -z noexecstack`；`HARDEN=0` 可關閉。`make hardening`（`tests/hardening/check.py`）用 readelf／otool 檢查 PIE、full RELRO、NX stack、stack protector、`*_chk` 呼叫，CI 每個建置都會跑；sanitizer 建置不開 FORTIFY）
- [x] 設定檔（INI 或 YAML 子集），並支援 log 輪替（`535d1c1`：`-c FILE`，INI 子集，`[capture]`／`[rules]`／`[vars]`／`[output]`／`[engine]`／`[security]`，範例與所有預設值在 `etc/simpleids.conf`。優先順序：內建預設 < 設定檔 < 命令列；每個設定都有 `section.key` 名稱，設定檔和命令列都經過同一個 `settings_set()` 驗證；未知的 section／key 是錯誤，所有錯誤以 `檔案:行號` 列出。輸入視為不可信：單行 ≤ 4096 bytes、檔案 ≤ 1 MB。log 依大小輪替：`--log-max-size`／`--log-max-files`，`ids.log` → `ids.log.1` … `.N`；rename 失敗時繼續寫並在下一個門檻重試。SIGHUP 也會重新開啟 log（配合外部 logrotate），新檔開不了就保留舊的。測試：unit `settings`、`test_cli.py` 的 config 與 rotation 情境、fuzz target `config`）
- [x] 統計輸出：pps、丟包率、flow 數、記憶體用量（`535d1c1`：`--stats-interval S` 每 S 秒（`-r` 用封包時間，live 用實際時間）在 log 寫一筆 EVE 風格的 `event_type:"stats"`，結束時再寫一筆；SIGUSR1 隨時寫一筆。內容：封包／bytes、區間 pps 與 Mbps、live 擷取的 `kernel_received`／`kernel_drops`／`if_drops`／`drop_rate`（`pcap_stats`）、decoder 計數、flow（active／peak／created／timed_out／evicted／table_bytes）、重組記憶體（目前／高峰／memcap）、應用層與偵測計數、`rss_peak_bytes`、log 輪替計數；`--measure-latency` 時另有每封包延遲的百分位數）
- [x] 效能基準測試：`make bench` 跑固定的 pcap，輸出 Mbps（`535d1c1`、`9d59969`：`tests/bench/bench.py` 新增 `--measure-latency` 量每封包延遲（直方圖，每 2 倍再分 8 格，avg／p50／p99／p99.9／max）與 `wait4` 量 peak RSS，RSS > 256 MB 就失敗；500 Mbit/s 目標只顯示不判定（雲端機器速度浮動）。callgrind 找到兩個熱點並優化（`9d59969`）：異常偵測的頻率表從線性 `strcmp` 掃描改成 SipHash 雜湊加 O(1) LRU，IPv4 位址字串不再經過 `inet_ntop`／`sprintf`，告警輸出逐 byte 相同）
- **驗收**：每個 fuzz target 累積 ≥ 24 小時沒有 crash，達到 §3.3 的效能目標。
  - ✅ 效能：`make bench`（release 建置，5 次取最快）10 條規則 802 Mbit/s、300 條規則 **670 Mbit/s**（下降 16.5%）；同一台機器同時間對照，Phase 4 為 448–457 Mbit/s、Phase 5 優化前 440–444 Mbit/s、優化後 624–705 Mbit/s，所以強化旗標與 seccomp 的成本在雜訊範圍內。每封包延遲 avg 2.0 µs、p50 144 ns、p99 15.4 µs、p99.9 32.8 µs。記憶體：peak RSS **79.6 MiB**（預設 65536 flows + 64 MB memcap，上限 256 MB）。
  - ⏳ fuzz 24 小時：本機 6 個 target 平行各跑 20 分鐘無 crash（decode 2.6 億次、dns 4.1 億次、tls 5470 萬次、http 500 萬次、rules 190 萬次、engine 178 萬次）；CI smoke 每次 push 跑。24 小時由 `fuzz.yml` nightly（每 target 每晚 3 小時，job summary 顯示累計 CPU 時數）累積，約 8 個晚上達標。
- **行為說明與已知限制**
  - sanitizer 建置（`make asan`）不進 seccomp，因為 LSan 需要 ptrace／clone；macOS ASan 同樣跳過 sandbox。
  - 降權後 log 輪替需要 log 所在目錄對新使用者可寫（rename 和建新檔都在目錄層級）；不可寫時會繼續寫原檔並計入 `rotate_errors`。SIGHUP 重讀規則時，規則檔也必須對新使用者可讀。
  - 統計輸出預設關閉（`--stats-interval 0`），只有 SIGUSR1 或設定後才寫。
  - `-R` 會取代設定檔裡的 `rules.path`，不是附加。
  - live 擷取改用 `pcap_dispatch` 迴圈（才能定時寫 stats 和處理訊號）；只有 live 擷取且仍是 root 時才警告「以 root 執行」。
  - seccomp allowlist 是針對 glibc + libpcap 的實際呼叫手動整理的；換 libc（例如 musl）或新版 libpcap 若用到新的 syscall，會以 159 結束並印出 syscall 編號，屆時再加進清單或用 `--no-sandbox`。

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
