# SimpleIDS

以 C + libpcap 撰寫的教學用網路入侵偵測系統（NIDS）。

- **規格與發展計畫**：@docs/ROADMAP.md（開始任何工作前先讀；完成項目要回頭勾選，並註記 commit）
- **目前進度**：Phase 4 完成（規則語言 v2、Aho-Corasick 預過濾 + PCRE2、threshold/detection_filter、SIGHUP 原子重載、`--test-rules`、300 條規則、規避測試集 98.7%、300 vs 10 條規則吞吐量只降 8.5%），接下來是 Phase 5（穩健性與維運）
- **溝通語言**：回覆使用繁體中文

## 建置與執行
- `make`：建置 `./SimpleIDS`，需要 libpcap 和 PCRE2（Ubuntu：`libpcap-dev libpcre2-dev pkg-config`；macOS：`brew install pcre2`）
- `make test`：單元測試 + pcap 回歸測試 + 規避測試集報告（`tests/evasion/report.py`，偵測率 < 95% 或有未記錄的漏報就失敗）+ CLI 測試（`tests/cli/test_cli.py`：`--test-rules`、SIGHUP 重載）+ 規則庫測試（`tests/rules/test_library.py`：每條 `rules/crs/` 規則都要命中自己的樣本，正常流量語料不能有任何告警）；`make asan`：用 ASan/UBSan 建置並跑全部測試；`make pcaps`：重新產生 `tests/pcaps/`；`make bench`：10 條 vs 全部規則的吞吐量比較（掉 ≥ 30% 就失敗）
- 即時監聽：`sudo ./SimpleIDS -i <iface>`（macOS 的 loopback 介面是 `lo0`，Linux 是 `lo`）
- 離線分析：`./SimpleIDS -r file.pcap`（不需要 root）；`-l` 指定 JSON log（`-` 輸出到 stdout），`-q` 不在終端機印告警
- 其他選項：`-f FILTER`（BPF，`-f ''` 不過濾）、`--max-flows N`、`--stream-depth SIZE`、`--stream-memcap SIZE`（SIZE 可加 K/M/G）、`--overlap first|last`、`--var NAME=VALUE`（規則變數，如 `HOME_NET`）
- `./SimpleIDS --test-rules [-R ...]`：只檢查規則（語法、重複 sid、效能警告），錯誤以 `檔案:行號` 回報，沒有錯誤時 exit 0
- `kill -HUP <pid>`：重新載入規則；新規則集必須零錯誤才會換上，否則保留舊規則
- 目錄結構：標頭檔在 `include/simpleids/`，程式碼依模組放在 `src/{core,decode,flow,stream,detect,anomaly,output,app,util}/`
- **macOS 注意**：如果 clang 找不到 `stdio.h`，代表 sysroot 指向的 SDK 不存在。可以加上 `-isysroot $(xcrun --show-sdk-path)`，或重新安裝 Command Line Tools。
- 必須在 repo 根目錄執行，因為規則檔是用相對路徑載入的（預設 `rules/*.rules` + `rules/crs/*.rules`）。`-R PATH` 可指定規則檔或目錄（目錄會載入其中所有 `*.rules`；可重複，會取代預設）。
- 規則：`rules/{http,tls,dns}.rules` 是核心規則（33 條），使用 sticky buffer（`http.uri; content:...`），buffer 必須跟規則協定（`http`/`tls`/`dns`）相符；`tcp`/`udp` 規則比對原始串流或封包。規則語言 v2 支援 `pcre`、`offset/depth/distance/within`、`startswith/endswith`、`fast_pattern`、`flow`、`threshold`/`detection_filter`、`alert/drop/pass`、`$VAR` 變數、`\` 續行（完整清單見 ROADMAP Phase 4）。
- 規則庫 `rules/crs/` 依 OWASP CRS 分類（913 掃描器、920/921 協定、930 LFI、931 RFI、932 RCE、933 PHP、934 通用、941 XSS、942 SQLi、943 session、944 Java），sid 前三碼就是 CRS 檔號（例如 942xxx）。異常告警的 sid 定義在 `include/simpleids/anomaly.h`（9000xx）。
- 告警語意：解析過的訊息（每個 HTTP 請求、TLS hello、DNS 查詢）各告警一次；原始 TCP 規則每個 flow 一次；原始 UDP 規則每個封包一次；命中 `pass` 規則的 flow 之後不再檢查。

## 開發慣例
- 修改程式後，一定要用 `-fsanitize=address,undefined` 編譯，並跑過測試。
- 處理封包和規則時，函式一律帶長度參數，不可以假設 payload 有 NUL 結尾。
- 每修一個偵測相關的 bug，都要補一個能重現該 bug 的測試案例：單元測試放 `tests/unit/`，端到端情境加進 `tests/regression/gen_pcaps.py` 再跑 `make pcaps`（產生的 pcap 和 `*.expected.json` 要一起 commit）。
- 單元測試裡的 payload 用 `exact_buf()` / `exact_bytes()` 放進剛好大小的 heap buffer，ASan 才抓得到越界讀取。
- 偵測在重組後的串流上進行（`src/core/engine.c` 的 `inspect_stream`）；新增應用層解析時，要能處理資料分好幾次送達，且不可假設一次拿到完整訊息。
- 回歸 pcap 需要額外 CLI 參數時，寫在 `gen_pcaps.py` 的 `emit(..., args=[...])`，會存進 `*.expected.json`。
- 新增規避手法時，加進 `tests/evasion/evasion_cases.py`；抓不到的要填 `known_miss` 原因，再跑 `make pcaps` 和 `python3 tests/evasion/report.py --markdown docs/EVASION.md`。
- 新增或修改 `rules/crs/` 的規則時，一定要在 `tests/rules/samples.py` 補對應樣本；誤報要加進 `CLEAN` 語料，再跑 `make library`。規則總數（核心 + 規則庫）上限 300（`tests/unit/test_rules.c` 會檢查）。
- 回歸測試和規避測試集固定只載入核心規則（`-R rules`），所以 `rules/crs/` 的變動不會改到 `tests/pcaps/*.expected.json`。
- 規則檔的 pcre 跳脫：`\\` 保留為 regex 跳脫，`\"`、`\;` 會被還原；content 裡的 `|` 和 `;` 要寫成 `|7c|`、`|3b|`。
- 不要 commit 編譯產物，例如 `SimpleIDS`、`*.o`、`__pycache__`、`build/`。
