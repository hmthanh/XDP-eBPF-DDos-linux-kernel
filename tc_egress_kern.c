// SPDX-License-Identifier: GPL-2.0
/*
 * tc_egress_kern.c — per-destination-IP token-bucket rate limiter.
 *
 * Attached as a clsact/egress classifier on the physical NIC. Drops
 * packets that would exceed the per-destination-IP egress cap.
 *
 * Default cap: 100 Mbit/s per dst IP (configurable via egr_config map).
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP        0x0800

#define DEFAULT_RATE_BPS    (100ULL * 1000 * 1000)       /* 100 Mbit/s */
#define DEFAULT_BURST_BYTES (DEFAULT_RATE_BPS / 8 / 20)  /* ~50 ms     */

#ifndef TC_ACT_OK
#define TC_ACT_OK   0
#endif
#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif

struct tb_state {
    __u64 tokens;
    __u64 last_ns;
};

enum egr_cfg {
    EGR_RATE_BPS = 0,
    EGR_BURST_BYTES,
    __EGR_CFG_MAX,
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, struct tb_state);
    __uint(max_entries, 2000000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} egress_tb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, __EGR_CFG_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} egr_config SEC(".maps");

static __always_inline __u64 cfg_u64(__u32 idx, __u64 def)
{
    __u64 *v = bpf_map_lookup_elem(&egr_config, &idx);
    return (v && *v) ? *v : def;
}

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    __u32 dst_ip  = iph->daddr;
    __u64 pkt_len = skb->len;
    __u64 now     = bpf_ktime_get_coarse_ns();

    __u64 rate_bps = cfg_u64(EGR_RATE_BPS,    DEFAULT_RATE_BPS);
    __u64 burst    = cfg_u64(EGR_BURST_BYTES, DEFAULT_BURST_BYTES);

    struct tb_state *s = bpf_map_lookup_elem(&egress_tb, &dst_ip);
    if (!s) {
        struct tb_state init = { .tokens = burst, .last_ns = now };
        bpf_map_update_elem(&egress_tb, &dst_ip, &init, BPF_ANY);
        s = bpf_map_lookup_elem(&egress_tb, &dst_ip);
        if (!s) return TC_ACT_OK;
    }

    __u64 delta_ns = now - s->last_ns;
    if (delta_ns > 1000000000ULL) delta_ns = 1000000000ULL;

    __u64 add = (rate_bps >> 3) * delta_ns / 1000000000ULL;
    __u64 new_tokens = s->tokens + add;
    if (new_tokens > burst) new_tokens = burst;

    s->last_ns = now;

    if (new_tokens < pkt_len) {
        s->tokens = new_tokens;
        return TC_ACT_SHOT;
    }

    s->tokens = new_tokens - pkt_len;
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
