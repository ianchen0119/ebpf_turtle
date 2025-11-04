#!/usr/bin/env python3
"""
簡化版效能測試 - 自動執行 ping 測試並顯示結果
"""

from bcc import BPF
from ctypes import c_int
from pyroute2 import IPRoute, IPDB
from simulation import Simulation
import time
import subprocess
import sys

ipr = IPRoute()
ipdb = IPDB(nl=ipr)

num_hosts = 2
null = open("/dev/null", "w")

class BridgeSimulation(Simulation):
    def __init__(self, ipdb):
        super(BridgeSimulation, self).__init__(ipdb)
        self.bridge_code = None

    def start(self):
        self.bridge_code = BPF(src_file="bridge.c")
        ingress_fn = self.bridge_code.load_func("handle_ingress", BPF.SCHED_CLS)
        egress_fn  = self.bridge_code.load_func("handle_egress", BPF.SCHED_CLS)
        conf       = self.bridge_code.get_table("conf")

        ebpf_bridge = ipdb.create(ifname="ebpf_br", kind="dummy").up().commit()
        ipr.tc("add", "ingress", ebpf_bridge.index, "ffff:")
        ipr.tc("add-filter", "bpf", ebpf_bridge.index, ":1", fd=egress_fn.fd,
           name=egress_fn.name, parent="ffff:", action="drop", classid=1)

        conf[c_int(0)] = c_int(ebpf_bridge.index)

        host_info = []
        for i in range(0, num_hosts):
            print("Launching host %i of %i" % (i + 1, num_hosts))
            ipaddr = "172.16.1.%d/24" % (100 + i)
            host_info.append(self._create_ns("host%d" % i, ipaddr=ipaddr,
                disable_ipv6=True))

        temp_index=1
        for host in host_info:
            ipr.tc("add", "ingress", host[1].index, "ffff:")
            ipr.tc("add-filter", "bpf", host[1].index, ":1", fd=ingress_fn.fd,
                   name=ingress_fn.name, parent="ffff:", action="drop", classid=1)
            conf[c_int(temp_index)] = c_int(host[1].index)
            temp_index=temp_index+1

        return self.bridge_code

def print_stats(bridge_code):
    """列印效能統計"""
    print("\n" + "="*80)
    print("eBPF Clone Redirect 效能統計")
    print("="*80)
    
    stats = bridge_code.get_table("stats")
    
    stats_names = {
        0: "Ingress (host→bridge)",
        1: "Egress Unicast (bridge→host)",
        2: "Egress Flood (bridge→所有 hosts)"
    }
    
    print("\n【摘要統計】")
    total_packets = 0
    for i in range(3):
        key = stats.Key(i)
        try:
            val = stats[key]
            if val.count > 0:
                total_packets += val.count
                avg_latency = val.total_latency_ns / val.count
                print(f"\n{stats_names[i]}:")
                print(f"  封包數:         {val.count:,}")
                print(f"  總延遲:         {val.total_latency_ns:,} ns")
                print(f"  平均延遲:       {avg_latency:.2f} ns ({avg_latency/1000:.2f} μs)")
        except KeyError:
            pass
    
    if total_packets == 0:
        print("\n⚠️  尚無統計資料（可能還沒有封包通過）")
        return
    
    print("\n【延遲分布直方圖 (log2)】")
    
    print("\nIngress Clone Redirect 延遲:")
    bridge_code["clone_redirect_lat_ingress"].print_log2_hist("延遲 (ns)")
    
    print("\nEgress Clone Redirect 延遲:")
    bridge_code["clone_redirect_lat_egress"].print_log2_hist("延遲 (ns)")
    
    print("\n【MAC 學習表】")
    mac2host = bridge_code.get_table("mac2host")
    count = 0
    for k, v in mac2host.items():
        mac_str = ':'.join(['%02x' % ((k.mac >> (i*8)) & 0xff) for i in range(6)])
        print(f"MAC: {mac_str} -> ifindex: {v.ifindex}, RX: {v.rx_pkts:,}, TX: {v.tx_pkts:,}")
        count += 1
    
    if count == 0:
        print("（學習表為空）")
    
    print("\n" + "="*80)

def main():
    sim = None
    bridge_code = None
    
    try:
        print("="*80)
        print("eBPF Bridge 效能測試")
        print("="*80)
        
        # 啟動環境
        sim = BridgeSimulation(ipdb)
        bridge_code = sim.start()
        
        print("\n✓ Bridge 環境就緒\n")
        time.sleep(2)
        
        # 初始 MAC 學習
        print("--- 初始 MAC 學習 (10 次 ping) ---")
        proc = subprocess.run(
            ["ip", "netns", "exec", "host0", "ping", "-c", "10", "-i", "0.2", "172.16.1.101"],
            capture_output=True
        )
        print("✓ MAC 學習完成\n")
        
        time.sleep(1)
        
        # 效能測試
        print("--- 執行效能測試 (1000 次 ping) ---")
        proc = subprocess.run(
            ["ip", "netns", "exec", "host0", "ping", "-c", "1000", "-i", "0.001", "172.16.1.101"],
            capture_output=True
        )
        
        if proc.returncode == 0:
            print("✓ 效能測試完成\n")
        else:
            print("⚠️  Ping 測試有部分失敗（這是正常的）\n")
        
        # 顯示統計
        print_stats(bridge_code)
        
    except KeyboardInterrupt:
        print("\n\n⚠️  使用者中斷")
        if bridge_code:
            print_stats(bridge_code)
    except Exception as e:
        print(f"\n❌ 錯誤: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("\n--- 清理環境 ---")
        if sim:
            for p in sim.processes:
                try:
                    p.kill()
                    p.wait()
                    p.release()
                except:
                    pass
        if "ebpf_br" in ipdb.interfaces:
            ipdb.interfaces["ebpf_br"].remove().commit()
        if sim:
            sim.release()
        ipdb.release()
        null.close()
        print("✓ 清理完成")

if __name__ == "__main__":
    if subprocess.run(["id", "-u"], capture_output=True).stdout.strip() != b"0":
        print("❌ 錯誤: 此腳本必須以 root 身分執行")
        print("請執行: sudo python3 simple_benchmark.py")
        sys.exit(1)
    
    main()
