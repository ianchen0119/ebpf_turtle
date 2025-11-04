#!/usr/bin/env python3
"""
eBPF Bridge Performance Benchmark Script

This script:
1. Starts the bridge environment
2. Generates test traffic between namespaces
3. Collects and displays performance statistics
"""

from bcc import BPF
from ctypes import c_int
from pyroute2 import IPRoute, IPDB
from simulation import Simulation
from netaddr import IPAddress
import time
import subprocess
import threading
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
        # Loading bpf functions/maps.
        self.bridge_code = BPF(src_file="bridge.c")
        ingress_fn = self.bridge_code.load_func("handle_ingress", BPF.SCHED_CLS)
        egress_fn  = self.bridge_code.load_func("handle_egress", BPF.SCHED_CLS)
        mac2host   = self.bridge_code.get_table("mac2host")
        conf       = self.bridge_code.get_table("conf")

        # Creating dummy interface behind which ebpf code will do bridging.
        ebpf_bridge = ipdb.create(ifname="ebpf_br", kind="dummy").up().commit()
        ipr.tc("add", "ingress", ebpf_bridge.index, "ffff:")
        ipr.tc("add-filter", "bpf", ebpf_bridge.index, ":1", fd=egress_fn.fd,
           name=egress_fn.name, parent="ffff:", action="drop", classid=1)

        # Passing bridge index number to dataplane module
        conf[c_int(0)] = c_int(ebpf_bridge.index)

        # Setup namespace and their interfaces for demostration.
        host_info = []
        for i in range(0, num_hosts):
            print("Launching host %i of %i" % (i + 1, num_hosts))
            ipaddr = "172.16.1.%d/24" % (100 + i)
            host_info.append(self._create_ns("host%d" % i, ipaddr=ipaddr,
                disable_ipv6=True))

        # Attach ingress programs
        temp_index=1
        for host in host_info:
            ipr.tc("add", "ingress", host[1].index, "ffff:")
            ipr.tc("add-filter", "bpf", host[1].index, ":1", fd=ingress_fn.fd,
                   name=ingress_fn.name, parent="ffff:", action="drop", classid=1)
            conf[c_int(temp_index)] = c_int(host[1].index)
            temp_index=temp_index+1

        return self.bridge_code

def print_stats(bridge_code):
    """Print performance statistics from eBPF maps"""
    print("\n" + "="*80)
    print("eBPF Clone Redirect Performance Statistics")
    print("="*80)
    
    # Get statistics table
    stats = bridge_code.get_table("stats")
    
    stats_names = {
        0: "Ingress (host->bridge)",
        1: "Egress Unicast (bridge->host)",
        2: "Egress Flood (bridge->all hosts)"
    }
    
    print("\n--- Summary Statistics ---")
    for i in range(3):
        key = stats.Key(i)
        try:
            val = stats[key]
            if val.count > 0:
                avg_latency = val.total_latency_ns / val.count
                print(f"\n{stats_names[i]}:")
                print(f"  Packets:        {val.count:,}")
                print(f"  Total Latency:  {val.total_latency_ns:,} ns")
                print(f"  Avg Latency:    {avg_latency:.2f} ns ({avg_latency/1000:.2f} μs)")
        except KeyError:
            pass
    
    # Print histograms
    print("\n--- Latency Histograms (log2) ---")
    
    print("\nIngress Clone Redirect Latency:")
    bridge_code["clone_redirect_lat_ingress"].print_log2_hist("latency (ns)")
    
    print("\nEgress Clone Redirect Latency:")
    bridge_code["clone_redirect_lat_egress"].print_log2_hist("latency (ns)")
    
    # MAC learning table
    print("\n--- MAC Learning Table ---")
    mac2host = bridge_code.get_table("mac2host")
    for k, v in mac2host.items():
        mac_str = ':'.join(['%02x' % ((k.mac >> (i*8)) & 0xff) for i in range(6)])
        print(f"MAC: {mac_str} -> ifindex: {v.ifindex}, RX: {v.rx_pkts}, TX: {v.tx_pkts}")
    
    print("\n" + "="*80)

def run_ping_test(duration=10, count=None):
    """Run ping test between namespaces"""
    print(f"\n--- Running ping test for {duration} seconds ---")
    
    if count is None:
        # Continuous ping
        cmd = ["ip", "netns", "exec", "host0", "ping", "-i", "0.001", "172.16.1.101"]
    else:
        cmd = ["ip", "netns", "exec", "host0", "ping", "-c", str(count), "172.16.1.101"]
    
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    if count is None:
        # Run for specified duration
        time.sleep(duration)
        proc.terminate()
        proc.wait()
    else:
        # Wait for completion
        proc.wait()
    
    print("Ping test completed")
    return proc

def run_iperf_test(duration=10):
    """Run iperf3 test between namespaces"""
    print(f"\n--- Running iperf3 test for {duration} seconds ---")
    
    # Start iperf3 server in host1
    server_proc = subprocess.Popen(
        ["ip", "netns", "exec", "host1", "iperf3", "-s"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    time.sleep(1)  # Wait for server to start
    
    # Run iperf3 client in host0
    client_proc = subprocess.Popen(
        ["ip", "netns", "exec", "host0", "iperf3", "-c", "172.16.1.101", "-t", str(duration)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    client_proc.wait()
    server_proc.terminate()
    server_proc.wait()
    
    print("iperf3 test completed")

def main():
    """Main benchmark function"""
    sim = None
    bridge_code = None
    
    try:
        print("Starting eBPF Bridge Benchmark")
        print("="*80)
        
        # Start bridge
        sim = BridgeSimulation(ipdb)
        bridge_code = sim.start()
        
        print("\n✓ Bridge environment ready")
        time.sleep(2)
        
        # Run initial ping to establish MAC learning
        print("\n--- Initial MAC learning (10 pings) ---")
        run_ping_test(count=10)
        
        time.sleep(1)
        
        # Choose test type
        test_type = input("\nSelect test type:\n1. Ping test (ICMP)\n2. iperf3 (TCP throughput)\n3. Both\nChoice [1-3]: ").strip()
        
        if test_type in ['1', '3']:
            # Ping test - high packet rate
            run_ping_test(duration=10)
        
        if test_type in ['2', '3']:
            # Check if iperf3 is available
            try:
                subprocess.run(["which", "iperf3"], check=True, capture_output=True)
                run_iperf_test(duration=10)
            except subprocess.CalledProcessError:
                print("\nWarning: iperf3 not found, skipping throughput test")
                print("Install with: sudo apt-get install iperf3")
        
        # Display statistics
        print_stats(bridge_code)
        
        # Keep running for manual tests
        print("\n--- Environment still running for manual tests ---")
        print("You can run commands like:")
        print("  sudo ip netns exec host0 ping 172.16.1.101")
        print("  sudo ip netns exec host0 iperf3 -c 172.16.1.101")
        input("\nPress Enter to stop and show final statistics...")
        
        # Final statistics
        print_stats(bridge_code)
        
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        if bridge_code:
            print_stats(bridge_code)
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("\n--- Cleaning up ---")
        if "sim" in locals() and sim:
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
        print("Cleanup completed")

if __name__ == "__main__":
    if subprocess.run(["id", "-u"], capture_output=True).stdout.strip() != b"0":
        print("Error: This script must be run as root")
        print("Please run: sudo python3 benchmark.py")
        sys.exit(1)
    
    main()
