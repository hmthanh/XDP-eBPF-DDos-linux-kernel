// SPDX-License-Identifier: GPL-2.0
/*
 * xdp_ddos_kern.c — XDP/eBPF L4 DDoS defence for a 200M-MAU WebSocket platform.
 *
 * Fast-path order (cheapest first):
 *   1. allowlist hit        → PASS
 *   2. blocklist hit        → DROP
 *   3. fragment (off != 0)  → DROP
 *   4. uRPF via bpf_fib_lookup (loose) → DROP if no route back
 *   5. protocol checks      (SYN flood, UDP amp, ICMP flood)
 *   6. global per-IP PPS
 *
 * All thresholds are read from config_map so userspace can hot-reload.
 * All map lookups honour verifier bounds; every packet pointer is bounded
 * before dereference. All error paths return XDP_PASS (fail-open).
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

/* --------------------------------------------------------------------- */
/* Protocol constants (vmlinux.h omits non-kernel-struct macros)          */
/* --------------------------------------------------------------------- */
#define ETH_P_IP        0x0800
#define IPPROTO_ICMP    1
#define IPPROTO_TCP     6
#define IPPROTO_UDP     17

/* TCP flag bits as found in byte 13 of the TCP header */
#define TCP_FLAG_FIN    0x01
#define TCP_FLAG_SYN    0x02
#define TCP_FLAG_RST    0x04
#define TCP_FLAG_PSH    0x08
#define TCP_FLAG_ACK    0x10

/* AF_INET for bpf_fib_lookup */
#define AF_INET         2

/* --------------------------------------------------------------------- */
/* Defaults — overridable at runtime through config_map                   */
/* --------------------------------------------------------------------- */
#define DEFAULT_WINDOW_NS           1000000000ULL  /* 1 s sliding window   */
#define DEFAULT_PPS_LIMIT           10000u         /* 10 kpps per src      */
#define DEFAULT_SYN_THRESHOLD       64u            /* SYNs/window per flow */
#define DEFAULT_UDP_AMP_THRESHOLD   512u           /* UDP payload bytes    */
#define DEFAULT_ICMP_PPS_LIMIT      100u           /* ICMP per src         */
#define EVENT_SUPPRESS_NS           1000000000ULL  /* 1 s event dedup      */

/* --------------------------------------------------------------------- */
/* Value types                                                            */
/* --------------------------------------------------------------------- */
struct rate_entry {
    __u64 ts_ns;        /* first packet of current window                  */
    __u32 pkt_count;    /* packets seen within window                      */
};

struct flow_key {
    __u32 src;
    __u16 dport;        /* stored in network byte order (as in TCP hdr)    */
    __u16 pad;
};

struct conn_state {
    __u64 first_seen_ns;
    __u32 syn_count;
    __u8  flags;        /* reserved for future state bits                  */
    __u8  _pad[3];
};

struct drop_event {
    __u64 ts_ns;
    __u32 src_ip;
    __u16 dport;
    __u8  reason;
    __u8  _pad;
};

/* --------------------------------------------------------------------- */
/* Enums shared with userspace                                            */
/* --------------------------------------------------------------------- */
enum stat_idx {
    STAT_PASS = 0,
    STAT_DROP_BLOCKLIST,
    STAT_DROP_RATE,
    STAT_DROP_SYN,
    STAT_DROP_SPOOF,
    STAT_DROP_UDP_AMP,
    STAT_DROP_ICMP,
    STAT_DROP_FRAG,
    __STAT_MAX,
};

enum cfg_key {
    CFG_PPS_LIMIT = 0,
    CFG_SYN_THRESHOLD,
    CFG_UDP_AMP_THRESHOLD,
    CFG_ICMP_PPS_LIMIT,
    CFG_WINDOW_NS_LO,       /* low 32 bits of window (ns fits in u32 @ 4s) */
    __CFG_MAX,
};

enum drop_reason {
    REASON_BLOCKLIST = 1,
    REASON_RATE,
    REASON_SYN,
    REASON_SPOOF,
    REASON_UDP_AMP,
    REASON_ICMP,
    REASON_FRAG,
};

/* --------------------------------------------------------------------- */
/* Maps                                                                   */
/* --------------------------------------------------------------------- */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, struct rate_entry);
    __uint(max_entries, 2000000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} rate_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, struct conn_state);
    __uint(max_entries, 4000000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} conn_tracker SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);                /* 0 = permanent, else ns expiry  */
    __uint(max_entries, 500000);
} blocklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 10000);
} allowlist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, __STAT_MAX);
} stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, __CFG_MAX);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

/* Auxiliary map: suppress duplicate perf events per src_ip / 1 s.
 * Not in the original enum but required to implement the "only emit
 * on first drop from a new src_ip within 1-second window" rule. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, __u64);                /* last event ts_ns               */
    __uint(max_entries, 200000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} event_ratelimit SEC(".maps");

/* --------------------------------------------------------------------- */
/* Helpers                                                                */
/* --------------------------------------------------------------------- */
static __always_inline void stat_incr(__u32 idx)
{
    __u64 *c = bpf_map_lookup_elem(&stats, &idx);
    if (c)
        (*c)++;   /* percpu, no atomics needed                             */
}

static __always_inline __u32 cfg_get(__u32 idx, __u32 def)
{
    __u32 *v = bpf_map_lookup_elem(&config_map, &idx);
    return (v && *v) ? *v : def;
}

static __always_inline __u64 cfg_window_ns(void)
{
    __u32 lo = cfg_get(CFG_WINDOW_NS_LO, (__u32)DEFAULT_WINDOW_NS);
    return (__u64)lo;  /* windows ≤ 4 s are sufficient for all use cases   */
}

static __always_inline void
maybe_emit(struct xdp_md *ctx, __u32 src_ip, __u16 dport, __u8 reason, __u64 now)
{
    __u64 *last = bpf_map_lookup_elem(&event_ratelimit, &src_ip);
    if (last && (now - *last) < EVENT_SUPPRESS_NS)
        return;

    bpf_map_update_elem(&event_ratelimit, &src_ip, &now, BPF_ANY);

    struct drop_event ev = {
        .ts_ns  = now,
        .src_ip = src_ip,
        .dport  = dport,
        .reason = reason,
    };
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
}

/* Loose uRPF: ask the kernel "where would I route to this source?".
 * If the lookup returns unreachable/blackhole/prohibit → spoofed.
 * NO_NEIGH and SUCCESS both mean a route exists → accept.
 * All other errors → fail-open. */
static __always_inline int urpf_spoofed(struct xdp_md *ctx, struct iphdr *iph)
{
    struct bpf_fib_lookup p = {};

    p.family      = AF_INET;
    p.l4_protocol = iph->protocol;
    p.tos         = iph->tos;
    p.tot_len     = bpf_ntohs(iph->tot_len);
    p.ifindex     = ctx->ingress_ifindex;
    /* Reverse-path: the source of the incoming packet becomes our target  */
    p.ipv4_src    = iph->daddr;
    p.ipv4_dst    = iph->saddr;

    long rc = bpf_fib_lookup(ctx, &p, sizeof(p), 0);

    switch (rc) {
    case BPF_FIB_LKUP_RET_SUCCESS:
    case BPF_FIB_LKUP_RET_NO_NEIGH:
    case BPF_FIB_LKUP_RET_NOT_FWDED:
        return 0;   /* either routable or we cannot prove spoofing         */
    case BPF_FIB_LKUP_RET_BLACKHOLE:
    case BPF_FIB_LKUP_RET_UNREACHABLE:
    case BPF_FIB_LKUP_RET_PROHIBIT:
        return 1;   /* definitively un-routable back → drop                */
    default:
        return 0;   /* unknown codes → fail-open                           */
    }
}

/* Update or insert a per-IP rate entry; return 1 if threshold exceeded.
 * Because LRU may evict between update and re-lookup, we treat update
 * failures as "not exceeded" (fail-open under memory pressure). */
static __always_inline int
rate_hit(__u32 src_ip, __u64 now, __u64 window_ns, __u32 limit)
{
    struct rate_entry *re = bpf_map_lookup_elem(&rate_counters, &src_ip);
    if (re) {
        if ((now - re->ts_ns) > window_ns) {
            re->ts_ns = now;
            re->pkt_count = 1;
            return 0;
        }
        __u32 c = __sync_add_and_fetch(&re->pkt_count, 1);
        return c > limit;
    }

    struct rate_entry init = { .ts_ns = now, .pkt_count = 1 };
    bpf_map_update_elem(&rate_counters, &src_ip, &init, BPF_ANY);
    return 0;
}

/* --------------------------------------------------------------------- */
/* Main XDP entry                                                         */
/* --------------------------------------------------------------------- */
SEC("xdp")
int xdp_ddos(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 now      = bpf_ktime_get_coarse_ns();

    /* ----- L2 parse ---------------------------------------------------- */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;                 /* malformed → fail-open         */

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        /* ARP/IPv6/other — out of scope for this defence (v1)            */
        stat_incr(STAT_PASS);
        return XDP_PASS;
    }

    /* ----- L3 parse (with IHL validation) ------------------------------ */
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u8 ihl_words = iph->ihl;
    if (ihl_words < 5)
        return XDP_PASS;                 /* malformed IP header            */

    __u32 ip_hdr_len = (__u32)ihl_words * 4;

    /* Strict: ensure the full IP header (including options) is present.
     * Verifier needs the comparison done on a bounded (unsigned) length. */
    if ((void *)eth + sizeof(*eth) + ip_hdr_len > data_end)
        return XDP_PASS;

    __u32 src_ip = iph->saddr;           /* network byte order             */

    /* ----- 1. Allowlist fast-pass ------------------------------------- */
    __u8 *allow = bpf_map_lookup_elem(&allowlist, &src_ip);
    if (allow && *allow) {
        stat_incr(STAT_PASS);
        return XDP_PASS;
    }

    /* ----- 2. Blocklist ----------------------------------------------- */
    __u64 *blocked_until = bpf_map_lookup_elem(&blocklist, &src_ip);
    if (__builtin_expect(blocked_until != NULL, 0)) {
        /* 0 = permanent; non-zero = expiry in ns                         */
        if (*blocked_until == 0 || *blocked_until > now) {
            stat_incr(STAT_DROP_BLOCKLIST);
            maybe_emit(ctx, src_ip, 0, REASON_BLOCKLIST, now);
            return XDP_DROP;
        }
        /* Expired entries are left for userspace GC (SIGHUP/reload).     */
    }

    /* ----- 3. Fragments ------------------------------------------------ */
    __u16 frag_off = bpf_ntohs(iph->frag_off);
    /* Top 3 bits are flags; bottom 13 are the offset. Drop offset != 0 */
    if (__builtin_expect((frag_off & 0x1FFF) != 0, 0)) {
        stat_incr(STAT_DROP_FRAG);
        maybe_emit(ctx, src_ip, 0, REASON_FRAG, now);
        return XDP_DROP;
    }

    /* ----- 4. uRPF spoof check ---------------------------------------- */
    if (__builtin_expect(urpf_spoofed(ctx, iph), 0)) {
        stat_incr(STAT_DROP_SPOOF);
        maybe_emit(ctx, src_ip, 0, REASON_SPOOF, now);
        return XDP_DROP;
    }

    /* ----- 5. Protocol-specific checks --------------------------------- */
    __u8  proto = iph->protocol;
    void *l4    = (void *)iph + ip_hdr_len;
    __u16 dport = 0;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        dport = bpf_ntohs(tcp->dest);

        /* Read the flags byte directly at offset 13 to avoid bitfield
         * portability headaches; byte is defined by RFC 793 layout.     */
        __u8 *tcp_b = (__u8 *)tcp;
        if ((void *)(tcp_b + 14) > data_end)
            return XDP_PASS;
        __u8 tcp_flags = tcp_b[13];

        /* SYN-only (no ACK/RST/FIN) — initial handshake attempt          */
        if ((tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_ACK |
                          TCP_FLAG_RST | TCP_FLAG_FIN)) == TCP_FLAG_SYN) {

            struct flow_key fk = {
                .src   = src_ip,
                .dport = tcp->dest,   /* keep net-order for key stability */
                .pad   = 0,
            };

            __u32 syn_thresh = cfg_get(CFG_SYN_THRESHOLD, DEFAULT_SYN_THRESHOLD);
            __u64 window_ns  = cfg_window_ns();

            struct conn_state *cs = bpf_map_lookup_elem(&conn_tracker, &fk);
            if (cs) {
                if ((now - cs->first_seen_ns) > window_ns) {
                    cs->first_seen_ns = now;
                    cs->syn_count     = 1;
                } else {
                    __u32 n = __sync_add_and_fetch(&cs->syn_count, 1);
                    if (__builtin_expect(n > syn_thresh, 0)) {
                        stat_incr(STAT_DROP_SYN);
                        maybe_emit(ctx, src_ip, dport, REASON_SYN, now);
                        return XDP_DROP;
                    }
                }
            } else {
                struct conn_state init = {
                    .first_seen_ns = now,
                    .syn_count     = 1,
                };
                bpf_map_update_elem(&conn_tracker, &fk, &init, BPF_ANY);
            }
        }

    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        dport          = bpf_ntohs(udp->dest);
        __u16 sport    = bpf_ntohs(udp->source);
        __u16 udp_len  = bpf_ntohs(udp->len);
        __u32 amp_lim  = cfg_get(CFG_UDP_AMP_THRESHOLD,
                                 DEFAULT_UDP_AMP_THRESHOLD);

        /* Heuristic: large responses sourced from commonly-abused
         * amplification ports (DNS, NTP, SSDP, mDNS, chargen).           */
        if (__builtin_expect(udp_len > amp_lim, 0)) {
            if (sport == 53  || sport == 123 || sport == 1900 ||
                sport == 5353 || sport == 19) {
                stat_incr(STAT_DROP_UDP_AMP);
                maybe_emit(ctx, src_ip, dport, REASON_UDP_AMP, now);
                return XDP_DROP;
            }
        }

    } else if (proto == IPPROTO_ICMP) {
        /* ICMP has no ports; dport stays 0. Handled in the unified rate
         * check below with a dedicated (lower) threshold.                */
    }

    /* ----- 6. Global per-IP rate check -------------------------------- */
    __u64 window_ns = cfg_window_ns();
    __u32 pps_limit;
    __u8  drop_stat, drop_reason;

    if (proto == IPPROTO_ICMP) {
        pps_limit   = cfg_get(CFG_ICMP_PPS_LIMIT, DEFAULT_ICMP_PPS_LIMIT);
        drop_stat   = STAT_DROP_ICMP;
        drop_reason = REASON_ICMP;
    } else {
        pps_limit   = cfg_get(CFG_PPS_LIMIT, DEFAULT_PPS_LIMIT);
        drop_stat   = STAT_DROP_RATE;
        drop_reason = REASON_RATE;
    }

    if (__builtin_expect(rate_hit(src_ip, now, window_ns, pps_limit), 0)) {
        stat_incr(drop_stat);
        maybe_emit(ctx, src_ip, dport, drop_reason, now);
        return XDP_DROP;
    }

    stat_incr(STAT_PASS);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
