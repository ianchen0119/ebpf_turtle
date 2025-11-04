// Copyright (c) PLUMgrid, Inc. // Licensed under the Apache License, Version 2.0 (the "License")
#include <bcc/proto.h>
//Total ports should be number of hosts attached + 1.
#define TOTAL_PORTS 3
struct mac_key {
  u64 mac;
};

struct host_info {
  u32 ifindex;
  u64 rx_pkts;
  u64 tx_pkts;
};

BPF_TABLE("hash", struct mac_key, struct host_info, mac2host, 10240);

struct config {
  int ifindex;
};

BPF_TABLE("hash", int, struct config, conf, TOTAL_PORTS);

// Performance measurement: histogram of clone_redirect latency in nanoseconds
BPF_HISTOGRAM(clone_redirect_lat_ingress, u64);
BPF_HISTOGRAM(clone_redirect_lat_egress, u64);

// Statistics counters
struct stats_key {
  u32 type; // 0: ingress, 1: egress unicast, 2: egress flood
};

struct stats_value {
  u64 count;
  u64 total_latency_ns;
};

BPF_TABLE("hash", struct stats_key, struct stats_value, stats, 3);

// Handle packets from (namespace outside) interface and forward it to bridge 
int handle_ingress(struct __sk_buff *skb) {
  //Lets assume that the packet is at 0th location of the memory.
  u8 *cursor = 0;
  struct mac_key src_key = {};
  struct host_info src_info = {};
  //Extract ethernet header from the memory and point cursor to payload of ethernet header.
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  // Extract bridge ifindex from the config file, that is populated by the python file while
  // creating the bridge.
  int zero = 0;
  struct config *cfg = conf.lookup(&zero);
  if (!cfg) return 1;
  src_key.mac = ethernet->src;
  src_info.ifindex = skb->ifindex;
  src_info.rx_pkts = 0;
  src_info.tx_pkts = 0;
  struct host_info *src_host = mac2host.lookup_or_init(&src_key, &src_info);
  lock_xadd(&src_host->rx_pkts, 1);
  
  // Performance measurement: measure bpf_clone_redirect latency
  u64 start_ts = bpf_ktime_get_ns();
  bpf_clone_redirect(skb, cfg->ifindex, 1/*ingress*/);
  u64 end_ts = bpf_ktime_get_ns();
  u64 latency = end_ts - start_ts;
  
  // Record in histogram
  clone_redirect_lat_ingress.increment(bpf_log2l(latency));
  
  // Update statistics
  struct stats_key skey = {.type = 0};
  struct stats_value szero = {};
  struct stats_value *sval = stats.lookup_or_init(&skey, &szero);
  if (sval) {
    lock_xadd(&sval->count, 1);
    lock_xadd(&sval->total_latency_ns, latency);
  }
  
  //bpf_trace_printk("[egress] sending traffic to ifindex=%d\n, pkt_type=%d", cfg->ifindex, ethernet->type);
  return 0;
}

// Handle packets inside the bridge and forward it to respective interface
int handle_egress(struct __sk_buff *skb) {
  u8 *cursor = 0;
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  struct mac_key dst_key = {ethernet->dst};
  struct host_info *dst_host = mac2host.lookup(&dst_key);
  struct config *cfg = 0;
  int cfg_index = 0;
  //If flow exists then just send the packet to dst host else flood it to all ports.
  if (dst_host) {
    // Unicast path - measure latency
    u64 start_ts = bpf_ktime_get_ns();
    bpf_clone_redirect(skb, dst_host->ifindex, 0/*ingress*/);
    u64 end_ts = bpf_ktime_get_ns();
    u64 latency = end_ts - start_ts;
    
    lock_xadd(&dst_host->tx_pkts, 1);
    clone_redirect_lat_egress.increment(bpf_log2l(latency));
    
    struct stats_key skey = {.type = 1};
    struct stats_value szero = {};
    struct stats_value *sval = stats.lookup_or_init(&skey, &szero);
    if (sval) {
      lock_xadd(&sval->count, 1);
      lock_xadd(&sval->total_latency_ns, latency);
    }
  } else {
    // Flooding path - measure total flood time
    u64 start_ts = bpf_ktime_get_ns();
    //if (ethernet->type != 0x0800) return 0;
    for ( int j=1;j<TOTAL_PORTS;j++ )
    {
      cfg_index = j;
      cfg = conf.lookup(&cfg_index);
      if (cfg) {
        bpf_clone_redirect(skb, cfg->ifindex, 0/*egress*/);
      }
    }
    u64 end_ts = bpf_ktime_get_ns();
    u64 latency = end_ts - start_ts;
    
    clone_redirect_lat_egress.increment(bpf_log2l(latency));
    
    struct stats_key skey = {.type = 2};
    struct stats_value szero = {};
    struct stats_value *sval = stats.lookup_or_init(&skey, &szero);
    if (sval) {
      lock_xadd(&sval->count, 1);
      lock_xadd(&sval->total_latency_ns, latency);
    }
  }
  return 0;
}
