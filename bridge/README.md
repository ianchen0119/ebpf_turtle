## eBPF Learning Bridge（學習型橋接器）

這個目錄示範如何用 BCC/eBPF 在 Linux 上實作一個簡單的二層學習型橋接器（learning bridge），透過 eBPF map 動態學習來源 MAC 與出口介面對應，為已知目的 MAC 做單播轉送，未知則進行泛洪（flooding）。

主要檔案：
- `bridge.c`：eBPF 程式（TC classifier），包含兩個函式 `handle_ingress` 與 `handle_egress`，以及兩張 eBPF map（`mac2host`、`conf`）。
- `bridge.py`：載入 eBPF、建立 dummy 橋介面、產生兩個 host 的 namespace 與 veth、將 eBPF 程式掛到各介面 TC ingress，並把 ifindex 寫入 `conf` map。
- `simulation.py`：建立/清理多個 network namespace 與 veth 的輔助工具。

已知限制：
- 由於 eBPF verifier 對可展開（unroll）的 loop 有限制，廣播（flooding）目標埠數量建議控制在 15 以內。
- 常數 `TOTAL_PORTS` 需設定為「主機數 + 1」（第 0 號留給橋 `ebpf_br`）。

---

## 架構總覽與資料流

邏輯上建立一個 dummy 介面 `ebpf_br` 作為「橋」。每個 host namespace 透過 veth 連到 root namespace 的對外端介面，我們在這些介面上掛載 eBPF 程式：

- `handle_ingress`（掛在每個 host 的對外介面的 TC ingress）：
	- 學習來源 MAC 出現在哪個 ifindex（寫入 `mac2host`）。
	- 將封包 clone 並以 ingress 方向導入 `ebpf_br`。
- `handle_egress`（掛在 `ebpf_br` 的 TC ingress）：
	- 以目的 MAC 查詢 `mac2host`，命中則單播轉送；未命中則對所有已配置埠做泛洪。

簡化資料流：
1) hostX → vethX（root 端）—[handle_ingress]→ ebpf_br
2) ebpf_br —[handle_egress]→ 目的介面（單播）或所有埠（泛洪）

---

## 元件說明

### bridge.c（eBPF 程式）

- `struct mac_key { u64 mac; }` 與 `struct host_info { u32 ifindex; u64 rx_pkts; u64 tx_pkts; }`
	- 透過 `BPF_TABLE("hash", struct mac_key, struct host_info, mac2host, 10240)` 建立學習表：來源 MAC → 入口 ifindex 與計數器。
- `struct config { int ifindex; }`
	- 透過 `BPF_TABLE("hash", int, struct config, conf, TOTAL_PORTS)` 存放橋與各埠對應：
		- key 0：橋 `ebpf_br` 的 ifindex。
		- key 1..N：各 host 的對外介面 ifindex（由 `bridge.py` 寫入）。
- `handle_ingress(struct __sk_buff *skb)`
	- 解析乙太標頭，使用 `lookup_or_init` 將來源 MAC 對應到 `skb->ifindex`；`lock_xadd` 增加 `rx_pkts`。
	- 讀取 `conf[0]`（橋的 ifindex），`bpf_clone_redirect(skb, cfg->ifindex, 1)` 將封包 clone 到 `ebpf_br` 的 ingress。
- `handle_egress(struct __sk_buff *skb)`
	- 查目的 MAC：命中 `mac2host` 就單播 `bpf_clone_redirect(..., 0)` 並增加 `tx_pkts`；未命中則對 `conf[1..TOTAL_PORTS-1]` 逐一泛洪。

備註：TC filter 在 Python 端安裝為 `action=drop`，因此原封包會被丟棄，只保留 clone 往下一站前進，達到「轉送」效果。

### bridge.py（載入與組網）

- 以 BCC 載入 `bridge.c` 並取得 `handle_ingress` 與 `handle_egress`。
- 建立 dummy 介面 `ebpf_br`，在其 TC ingress 掛上 `handle_egress`。
- 建立兩個 host namespace 與 veth（可調整 `num_hosts`）。
- 在每個 host 對外介面 TC ingress 掛上 `handle_ingress`，並更新 `conf`：
	- `conf[0] = ebpf_br.index`
	- `conf[1] = host0_out_ifindex`、`conf[2] = host1_out_ifindex`、...

注意：程式內含 Python 2 與 Python 3 混合語法（例如 `except Exception,e:`），若使用 Python 3，請改為 `except Exception as e:`。

### simulation.py（模擬輔助）

- 以 pyroute2 建立/移除 network namespace、veth pair，並設定 IP/MAC。
- 協助在指定介面上安裝 TC ingress 與 BPF filter。

---

## 封包處理流程（細節）

1) host 發包 → 到達 root 端 veth 介面（host 外側）
	 - `handle_ingress` 讀乙太來源 MAC，學習到 `mac2host[mac] = {ifindex=skb->ifindex,...}`。
	 - clone 成一份新封包，送往 `conf[0]` 所指的 `ebpf_br` ingress。
2) `ebpf_br` 收到 clone 封包
	 - `handle_egress` 以目的 MAC 查 `mac2host`：
		 - 命中：單播轉送到對應 ifindex。
		 - 未命中：對 `conf` 列出的各埠進行泛洪。

---

## 需求與相依

- Linux（需具備 tc/cls_bpf 與 eBPF 支援）
- 以 root 權限執行（載入 eBPF、建立 qdisc 與 netns）
- 套件：
  - BCC（含 Python 介面）
  - pyroute2、netaddr

安裝依賴套件：
```bash
# 使用提供的安裝腳本（支援 Ubuntu/Debian/Fedora/Arch）
sudo ./install_deps.sh

# 或手動安裝（Ubuntu/Debian）
sudo apt-get install python3-bpfcc bpfcc-tools linux-headers-$(uname -r)
sudo apt-get install python3-pyroute2 python3-netaddr
```

---

## 效能量測

本專案已加入 `bpf_clone_redirect` 的效能量測功能。

### 測試結果摘要

在測試環境中（Ubuntu 22.04, Kernel 6.12.6），`bpf_clone_redirect` 的效能表現：

- **Ingress 路徑**：平均延遲 **~132 ns** (0.13 μs)
- **Egress 單播**：平均延遲 **~184 ns** (0.18 μs)
- **Egress 泛洪**：平均延遲 **~2.2 μs** (2 hosts)

90% 以上的封包延遲集中在 64-255 ns 範圍，展現出優異且穩定的效能。

完整測試結果請參閱 [RESULTS.md](RESULTS.md)。

### 快速開始

```bash
cd bridge
sudo ./quick_test.sh
```

或使用簡化版（無互動，自動測試）：

```bash
sudo python3 simple_benchmark.py
```

### 量測項目

- **延遲統計**：每次 `bpf_clone_redirect` 呼叫的執行時間（奈秒級）
- **直方圖**：延遲分布（log2 刻度）
- **分類統計**：
  - Ingress (host→bridge)
  - Egress Unicast (bridge→單一 host)
  - Egress Flood (bridge→所有 hosts)

### 測試選項

1. **Ping 測試** - 高封包率 ICMP 測試
2. **iperf3** - TCP 吞吐量測試
3. **兩者皆測**

詳細說明請參閱 [BENCHMARK.md](BENCHMARK.md)。

---## 如何執行（示意）

以下命令僅作為參考，實際環境可能需 root 權限與套件安裝：

```bash
# 於專案根目錄，以 root 身分執行（或使用 sudo）
python bridge/bridge.py

# 程式完成後會暫停在 "Press enter to quit:"，此時可在另一終端測試：
sudo ip netns exec host0 ping -c 3 172.16.1.101
```

結束時在原視窗按 Enter 即會自動清理 `ebpf_br` 與各 namespace/veth。

---

## 驗證與觀察

- 介面/濾器狀態：
	- `ip link`、`tc filter show dev <ifname> ingress` 檢查是否已掛載。
- 互通測試：
	- 互 ping 首次會因未知目的 MAC 而觸發泛洪；ARP/ICMP 後表項被學習，後續走單播。
- 進一步觀察：
	- 可擴充 `bridge.py`，藉由 `bridge_code.get_table("mac2host")` 列印學習表與計數器。

---

## 限制與注意事項

- Loop 展開限制：泛洪目標埠數量建議 ≤ 15。
- `TOTAL_PORTS` 為編譯期常數，需手動對齊 host 數量（= host 數 + 1）。
- 未實作 aging：學習到的 MAC → ifindex 對應不會自動過期；若拓樸變動，需等待來源重新出現覆寫。
- 泛洪未排除來源埠：在橋端做泛洪時未特別排除來源，來源可能收到未知單播的回送；可在程式中加入排除邏輯。
- 相容性：本範例使用 BCC 舊式巨集（`BPF_TABLE` 與 `<bcc/proto.h>`）。在新環境可考慮改用 `BPF_HASH` 或 libbpf/CO-RE。

---

## 可能的改進方向

- 學習表 aging（LRU map 或使用者空間週期清理）。
- 泛洪排除來源埠、或以位元陣列（bitmap）加速有效埠走訪。
- 將 `TOTAL_PORTS` 改為動態：以 map 管理有效埠集合與計數，移除編譯期限制。
- 可視化/除錯：提供 CLI 或週期列印 `mac2host`/`conf` 的工具。
- 效能：改以 XDP（需重新設計 redirect 流程）或遷移至 libbpf/CO-RE。

---

## 目錄與檔案對照

- `bridge.c`：eBPF 學習與轉送邏輯（TC）。
- `bridge.py`：載入 eBPF、建立 `ebpf_br` 與 host netns/veth、掛載 TC、寫入 `conf`。
- `simulation.py`：netns/veth 的建立/清理與 TC 輔助。
