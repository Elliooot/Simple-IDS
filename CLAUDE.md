# SimpleIDS

以 C + libpcap 撰寫的教學用網路入侵偵測系統（NIDS）。

- **規格與發展計畫**：@docs/ROADMAP.md（開始任何工作前先讀；完成項目要回頭勾選，並註記 commit）
- **目前進度**：Phase 3 完成（HTTP 正規化與 `http.*` 緩衝區、TLS SNI/ALPN/JA3/JA4/ECH、DNS、規避測試集 95.9%），接下來是 Phase 4（偵測引擎強化）
- **溝通語言**：回覆使用繁體中文

## 建置與執行
- `make`：建置 `./SimpleIDS`，需要 libpcap（Ubuntu 套件為 `libpcap-dev`）
- `make test`：單元測試 + pcap 回歸測試 + 規避測試集報告（`tests/evasion/report.py`，偵測率 < 95% 或有未記錄的漏報就失敗）；`make asan`：用 ASan/UBSan 建置並跑全部測試；`make pcaps`：重新產生 `tests/pcaps/`
- 即時監聽：`sudo ./SimpleIDS -i <iface>`（macOS 的 loopback 介面是 `lo0`，Linux 是 `lo`）
- 離線分析：`./SimpleIDS -r file.pcap`（不需要 root）；`-l` 指定 JSON log（`-` 輸出到 stdout），`-q` 不在終端機印告警
- 其他選項：`-f FILTER`（BPF，`-f ''` 不過濾）、`--max-flows N`、`--stream-depth SIZE`、`--stream-memcap SIZE`（SIZE 可加 K/M/G）、`--overlap first|last`
- 目錄結構：標頭檔在 `include/simpleids/`，程式碼依模組放在 `src/{core,decode,flow,stream,detect,anomaly,output,app,util}/`
- **macOS 注意**：如果 clang 找不到 `stdio.h`，代表 sysroot 指向的 SDK 不存在。可以加上 `-isysroot $(xcrun --show-sdk-path)`，或重新安裝 Command Line Tools。
- 必須在 repo 根目錄執行，因為規則檔是用相對路徑載入的（`rules/*.rules`）。`-R FILE` 可指定規則檔（可重複，會取代預設）。
- 規則：`rules/{http,tls,dns}.rules` 使用 sticky buffer（`http.uri; content:...`），buffer 必須跟規則協定（`http`/`tls`/`dns`）相符；`tcp`/`udp` 規則比對原始串流或封包。異常告警的 sid 定義在 `include/simpleids/anomaly.h`（9000xx）。

## 開發慣例
- 修改程式後，一定要用 `-fsanitize=address,undefined` 編譯，並跑過測試。
- 處理封包和規則時，函式一律帶長度參數，不可以假設 payload 有 NUL 結尾。
- 每修一個偵測相關的 bug，都要補一個能重現該 bug 的測試案例：單元測試放 `tests/unit/`，端到端情境加進 `tests/regression/gen_pcaps.py` 再跑 `make pcaps`（產生的 pcap 和 `*.expected.json` 要一起 commit）。
- 單元測試裡的 payload 用 `exact_buf()` / `exact_bytes()` 放進剛好大小的 heap buffer，ASan 才抓得到越界讀取。
- 偵測在重組後的串流上進行（`src/core/engine.c` 的 `inspect_stream`）；新增應用層解析時，要能處理資料分好幾次送達，且不可假設一次拿到完整訊息。
- 回歸 pcap 需要額外 CLI 參數時，寫在 `gen_pcaps.py` 的 `emit(..., args=[...])`，會存進 `*.expected.json`。
- 新增規避手法時，加進 `tests/evasion/evasion_cases.py`；抓不到的要填 `known_miss` 原因，再跑 `make pcaps` 和 `python3 tests/evasion/report.py --markdown docs/EVASION.md`。
- 不要 commit 編譯產物，例如 `SimpleIDS`、`*.o`、`__pycache__`。
