# SimpleIDS

以 C + libpcap 撰寫的教學用網路入侵偵測系統（NIDS）。

- **規格與發展計畫**：@docs/ROADMAP.md（開始任何工作前先讀；完成項目要回頭勾選，並註記 commit）
- **目前進度**：Phase 1 完成，接下來是 Phase 1.5（修正 B1–B16）
- **溝通語言**：回覆使用繁體中文

## 建置與執行
- `make`：建置 `./SimpleIDS`，需要 libpcap（Ubuntu 套件為 `libpcap-dev`）
- 執行：`sudo ./SimpleIDS <iface>`。macOS 的 loopback 介面是 `lo0`，Linux 是 `lo`。
- **macOS 注意**：如果 clang 找不到 `stdio.h`，代表 sysroot 指向的 SDK 不存在。可以加上 `-isysroot $(xcrun --show-sdk-path)`，或重新安裝 Command Line Tools。
- 必須在 repo 根目錄執行，因為規則檔是用相對路徑載入的（`rules/*.rules`）。

## 開發慣例
- 修改程式後，一定要用 `-fsanitize=address,undefined` 編譯，並跑過測試。
- 處理封包和規則時，函式一律帶長度參數，不可以假設 payload 有 NUL 結尾。
- 每修一個偵測相關的 bug，都要補一個能重現該 bug 的測試案例。
- 不要 commit 編譯產物，例如 `SimpleIDS`、`*.o`、`__pycache__`。
