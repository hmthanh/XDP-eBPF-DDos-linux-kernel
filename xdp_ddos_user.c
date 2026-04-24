// SPDX-License-Identifier: GPL-2.0
/*
 * xdp_ddos_user.c — userspace controller for xdp_ddos_kern.c
 *
 * Responsibilities:
 *   - load/attach the BPF program via libbpf skeleton
 *   - pin all maps under /sys/fs/bpf/ddos/
 *   - parse /etc/ddos/blocklist.txt (CIDR or bare IP, # comments)
 *   - poll perf_event ring, emit JSON drop events to stdout
 *   - expose a UNIX socket (/run/ddos.sock) for runtime control
 *   - handle SIGHUP (reload), SIGTERM/SIGINT (graceful shutdown)
 *
 * Build:  see Makefile
 * Deps:   libbpf ≥ 1.3, libelf, zlib
 */

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "xdp_ddos.skel.h"

#define PIN_DIR         "/sys/fs/bpf/ddos"
#define SOCK_PATH       "/run/ddos.sock"
#define BLOCKLIST_PATH  "/etc/ddos/blocklist.txt"
#define LOG_DIR         "/var/log/ddos"

/* Must match kernel enums exactly */
enum stat_idx {
    STAT_PASS = 0, STAT_DROP_BLOCKLIST, STAT_DROP_RATE, STAT_DROP_SYN,
    STAT_DROP_SPOOF, STAT_DROP_UDP_AMP, STAT_DROP_ICMP, STAT_DROP_FRAG,
    __STAT_MAX,
};
static const char *STAT_NAMES[__STAT_MAX] = {
    "pass", "drop_blocklist", "drop_rate", "drop_syn",
    "drop_spoof", "drop_udp_amp", "drop_icmp", "drop_frag",
};

enum cfg_key {
    CFG_PPS_LIMIT = 0, CFG_SYN_THRESHOLD, CFG_UDP_AMP_THRESHOLD,
    CFG_ICMP_PPS_LIMIT, CFG_WINDOW_NS_LO, __CFG_MAX,
};
static const char *CFG_NAMES[__CFG_MAX] = {
    "pps_limit", "syn_threshold", "udp_amp_threshold",
    "icmp_pps_limit", "window_ns",
};

enum drop_reason {
    REASON_BLOCKLIST = 1, REASON_RATE, REASON_SYN, REASON_SPOOF,
    REASON_UDP_AMP, REASON_ICMP, REASON_FRAG,
};
static const char *REASON_NAMES[] = {
    [REASON_BLOCKLIST] = "BLOCKLIST",
    [REASON_RATE]      = "RATE",
    [REASON_SYN]       = "SYN_FLOOD",
    [REASON_SPOOF]     = "SPOOF",
    [REASON_UDP_AMP]   = "UDP_AMP",
    [REASON_ICMP]      = "ICMP_FLOOD",
    [REASON_FRAG]      = "FRAGMENT",
};

struct drop_event {
    __u64 ts_ns;
    __u32 src_ip;
    __u16 dport;
    __u8  reason;
    __u8  _pad;
};

/* --------------------------------------------------------------------- */
/* Globals (daemon is single-process; a mutex guards map mutations)       */
/* --------------------------------------------------------------------- */
static struct xdp_ddos_bpf *g_skel;
static int g_ifindex;
static char g_ifname[IFNAMSIZ];
static __u32 g_xdp_flags;
static volatile sig_atomic_t g_should_exit;
static volatile sig_atomic_t g_should_reload;
static int g_wake_fd = -1;   /* eventfd used to break out of perf_buffer__poll */
static pthread_mutex_t g_map_lock = PTHREAD_MUTEX_INITIALIZER;

static void logmsg(const char *level, const char *fmt, ...)
{
    char ts[64];
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);

    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "%s [%s] ", ts, level);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

/* --------------------------------------------------------------------- */
/* Helpers                                                                */
/* --------------------------------------------------------------------- */
static int ensure_dir(const char *path, mode_t mode)
{
    if (mkdir(path, mode) == 0 || errno == EEXIST)
        return 0;
    logmsg("ERROR", "mkdir %s: %s", path, strerror(errno));
    return -1;
}

static int bump_memlock(void)
{
    struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        logmsg("WARN", "setrlimit(MEMLOCK): %s (continuing — systemd unit "
                       "should have already set LimitMEMLOCK=infinity)",
               strerror(errno));
        return -1;
    }
    return 0;
}

/* Pin all maps used by this daemon into PIN_DIR. Called after load.     */
static int pin_maps(struct xdp_ddos_bpf *skel)
{
    struct {
        struct bpf_map *m;
        const char     *name;
    } pins[] = {
        { skel->maps.rate_counters,  "rate_counters"   },
        { skel->maps.conn_tracker,   "conn_tracker"    },
        { skel->maps.blocklist,      "blocklist"       },
        { skel->maps.allowlist,      "allowlist"       },
        { skel->maps.stats,          "stats"           },
        { skel->maps.config_map,     "config_map"      },
        { skel->maps.events,         "events"          },
        { skel->maps.event_ratelimit,"event_ratelimit" },
    };

    for (size_t i = 0; i < sizeof(pins)/sizeof(pins[0]); i++) {
        char path[256];
        snprintf(path, sizeof(path), PIN_DIR "/%s", pins[i].name);
        /* Unpin pre-existing stale pin first — idempotent restart.      */
        unlink(path);
        if (bpf_map__pin(pins[i].m, path)) {
            logmsg("ERROR", "pin %s: %s", pins[i].name, strerror(errno));
            return -1;
        }
    }
    return 0;
}

/* Attach XDP; try native driver mode first, fall back to SKB mode.     */
static int attach_xdp(struct xdp_ddos_bpf *skel, int ifindex, __u32 *out_flags)
{
    int prog_fd = bpf_program__fd(skel->progs.xdp_ddos);

    /* Try DRV (native) mode                                             */
    __u32 flags = XDP_FLAGS_DRV_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;
    int err = bpf_xdp_attach(ifindex, prog_fd, flags, NULL);
    if (err == 0) {
        *out_flags = flags;
        logmsg("INFO", "attached XDP in DRV (native) mode on ifindex=%d", ifindex);
        return 0;
    }
    if (err != -EOPNOTSUPP && err != -ENOTSUP) {
        logmsg("ERROR", "XDP attach (DRV): %s", strerror(-err));
        return err;
    }

    /* Fall back to SKB (generic) mode                                   */
    flags = XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;
    err = bpf_xdp_attach(ifindex, prog_fd, flags, NULL);
    if (err) {
        logmsg("ERROR", "XDP attach (SKB): %s", strerror(-err));
        return err;
    }
    *out_flags = flags;
    logmsg("WARN", "NIC does not support native XDP, using SKB mode — "
                   "performance reduced");
    return 0;
}

/* --------------------------------------------------------------------- */
/* Blocklist I/O                                                          */
/* --------------------------------------------------------------------- */
static int parse_cidr(const char *line, __u32 *net_out, int *plen_out)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "%s", line);
    char *slash = strchr(buf, '/');
    int plen = 32;
    if (slash) {
        *slash = 0;
        plen = atoi(slash + 1);
        if (plen < 0 || plen > 32) return -1;
    }
    struct in_addr a;
    if (inet_pton(AF_INET, buf, &a) != 1) return -1;

    __u32 mask = plen == 0 ? 0 : htonl(0xFFFFFFFFu << (32 - plen));
    *net_out  = a.s_addr & mask;
    *plen_out = plen;
    return 0;
}

static void trim(char *s)
{
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n-1])) s[--n] = 0;
    while (*s && isspace((unsigned char)*s)) memmove(s, s+1, strlen(s));
}

/* Insert a CIDR into the blocklist map. For prefixes > /20 we expand
 * to individual /32 entries (≤ 4096 addresses). Wider nets log a warn
 * and insert only the network address — see README for the LPM_TRIE
 * upgrade path (tracked, not a code stub). */
static int blocklist_insert_cidr(int map_fd, const char *cidr, __u64 until_ns)
{
    __u32 net;
    int plen;
    if (parse_cidr(cidr, &net, &plen) < 0) {
        logmsg("WARN", "blocklist: bad CIDR '%s'", cidr);
        return -1;
    }

    if (plen >= 20) {
        __u32 host_count = plen == 32 ? 1u : (1u << (32 - plen));
        __u32 net_h = ntohl(net);
        for (__u32 i = 0; i < host_count; i++) {
            __u32 ip = htonl(net_h + i);
            int err = bpf_map_update_elem(map_fd, &ip, &until_ns, BPF_ANY);
            if (err == -ENOMEM) {
                logmsg("WARN", "blocklist: ENOMEM at %u entries; stopping",
                       i);
                return 0;
            }
            if (err) {
                logmsg("WARN", "blocklist: update ip=0x%08x err=%s",
                       ntohl(ip), strerror(-err));
            }
        }
    } else {
        logmsg("WARN", "blocklist: CIDR /%d > /20 too wide for hash map; "
                       "inserting only network address %s (upgrade to "
                       "LPM_TRIE tracked in README)", plen, cidr);
        int err = bpf_map_update_elem(map_fd, &net, &until_ns, BPF_ANY);
        if (err && err != -ENOMEM)
            logmsg("WARN", "blocklist: update err=%s", strerror(-err));
    }
    return 0;
}

static int load_blocklist_file(int map_fd, const char *path, size_t *inserted)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        if (errno == ENOENT) {
            logmsg("INFO", "no blocklist file at %s — starting empty", path);
            *inserted = 0;
            return 0;
        }
        logmsg("ERROR", "open %s: %s", path, strerror(errno));
        return -1;
    }

    char line[128];
    size_t count = 0;
    while (fgets(line, sizeof(line), f)) {
        char *hash = strchr(line, '#');
        if (hash) *hash = 0;
        trim(line);
        if (!*line) continue;

        if (blocklist_insert_cidr(map_fd, line, 0 /* permanent */) == 0)
            count++;
    }
    fclose(f);
    *inserted = count;
    return 0;
}

/* --------------------------------------------------------------------- */
/* Perf buffer — drop events                                              */
/* --------------------------------------------------------------------- */
static void format_ts(__u64 ts_ns_since_boot, char *out, size_t outlen)
{
    /* ts is CLOCK_MONOTONIC_COARSE ns; convert to wall time via offset  */
    struct timespec ts_mono, ts_real;
    clock_gettime(CLOCK_MONOTONIC, &ts_mono);
    clock_gettime(CLOCK_REALTIME,  &ts_real);

    __int64_t mono_ns = (__int64_t)ts_mono.tv_sec * 1000000000LL + ts_mono.tv_nsec;
    __int64_t real_ns = (__int64_t)ts_real.tv_sec * 1000000000LL + ts_real.tv_nsec;
    __int64_t offset  = real_ns - mono_ns;

    __int64_t wall_ns = (__int64_t)ts_ns_since_boot + offset;
    time_t secs = (time_t)(wall_ns / 1000000000LL);
    long   msec = (long)((wall_ns / 1000000LL) % 1000LL);

    struct tm tm;
    gmtime_r(&secs, &tm);
    char base[64];
    strftime(base, sizeof(base), "%Y-%m-%dT%H:%M:%S", &tm);
    snprintf(out, outlen, "%s.%03ldZ", base, msec);
}

static void on_drop_event(void *ctx, int cpu, void *data, __u32 size)
{
    (void)ctx; (void)cpu;
    if (size < sizeof(struct drop_event)) return;
    const struct drop_event *e = data;

    char ts[48], ip[INET_ADDRSTRLEN];
    format_ts(e->ts_ns, ts, sizeof(ts));
    struct in_addr a = { .s_addr = e->src_ip };
    inet_ntop(AF_INET, &a, ip, sizeof(ip));

    const char *reason = (e->reason < sizeof(REASON_NAMES)/sizeof(REASON_NAMES[0]) &&
                          REASON_NAMES[e->reason]) ? REASON_NAMES[e->reason] : "UNKNOWN";

    printf("{\"ts\":\"%s\",\"src_ip\":\"%s\",\"dport\":%u,"
           "\"reason\":\"%s\",\"action\":\"DROP\"}\n",
           ts, ip, (unsigned)e->dport, reason);
    fflush(stdout);
}

static void on_drop_lost(void *ctx, int cpu, __u64 lost)
{
    (void)ctx;
    logmsg("WARN", "perf buffer lost %llu events on cpu %d",
           (unsigned long long)lost, cpu);
}

/* --------------------------------------------------------------------- */
/* Stats aggregation                                                      */
/* --------------------------------------------------------------------- */
static int dump_stats_json(int stats_fd, char *out, size_t outlen)
{
    int ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0) ncpus = sysconf(_SC_NPROCESSORS_CONF);

    __u64 *vals = calloc(ncpus, sizeof(__u64));
    if (!vals) return -1;

    size_t off = 0;
    off += snprintf(out + off, outlen - off, "{");
    bool first = true;
    for (__u32 i = 0; i < __STAT_MAX; i++) {
        if (bpf_map_lookup_elem(stats_fd, &i, vals) != 0)
            continue;
        __u64 sum = 0;
        for (int c = 0; c < ncpus; c++) sum += vals[c];
        off += snprintf(out + off, outlen - off, "%s\"%s\":%llu",
                        first ? "" : ",", STAT_NAMES[i],
                        (unsigned long long)sum);
        first = false;
    }
    snprintf(out + off, outlen - off, "}\n");
    free(vals);
    return 0;
}

/* --------------------------------------------------------------------- */
/* Control socket — simple line protocol                                  */
/* --------------------------------------------------------------------- */
static int config_set(int cfg_fd, const char *key, const char *val)
{
    __u32 idx = 0;
    for (__u32 i = 0; i < __CFG_MAX; i++) {
        if (strcmp(key, CFG_NAMES[i]) == 0) { idx = i; goto found; }
    }
    return -1;
found: ;
    errno = 0;
    unsigned long v = strtoul(val, NULL, 10);
    if (errno) return -1;
    __u32 v32 = (__u32)v;
    return bpf_map_update_elem(cfg_fd, &idx, &v32, BPF_ANY);
}

static int handle_cmd(int cfd, char *line)
{
    char reply[8192];
    int blk_fd = bpf_map__fd(g_skel->maps.blocklist);
    int sts_fd = bpf_map__fd(g_skel->maps.stats);
    int cfg_fd = bpf_map__fd(g_skel->maps.config_map);

    char *tok = strtok(line, " \t\r\n");
    if (!tok) { dprintf(cfd, "ERR empty\n"); return 0; }

    if (strcmp(tok, "block") == 0) {
        char *ip  = strtok(NULL, " \t\r\n");
        char *sec = strtok(NULL, " \t\r\n");
        if (!ip) { dprintf(cfd, "ERR usage: block <ip> [seconds]\n"); return 0; }
        struct in_addr a;
        if (inet_pton(AF_INET, ip, &a) != 1) {
            dprintf(cfd, "ERR bad ip\n"); return 0;
        }
        __u64 until_ns = 0;
        if (sec) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            __u64 now_ns = (__u64)now.tv_sec * 1000000000ULL + now.tv_nsec;
            until_ns = now_ns + (__u64)strtoull(sec, NULL, 10) * 1000000000ULL;
        }
        __u32 key = a.s_addr;
        pthread_mutex_lock(&g_map_lock);
        int err = bpf_map_update_elem(blk_fd, &key, &until_ns, BPF_ANY);
        pthread_mutex_unlock(&g_map_lock);
        if (err) dprintf(cfd, "ERR %s\n", strerror(-err));
        else     dprintf(cfd, "OK\n");

    } else if (strcmp(tok, "unblock") == 0) {
        char *ip = strtok(NULL, " \t\r\n");
        if (!ip) { dprintf(cfd, "ERR usage: unblock <ip>\n"); return 0; }
        struct in_addr a;
        if (inet_pton(AF_INET, ip, &a) != 1) {
            dprintf(cfd, "ERR bad ip\n"); return 0;
        }
        __u32 key = a.s_addr;
        pthread_mutex_lock(&g_map_lock);
        int err = bpf_map_delete_elem(blk_fd, &key);
        pthread_mutex_unlock(&g_map_lock);
        if (err && err != -ENOENT) dprintf(cfd, "ERR %s\n", strerror(-err));
        else                       dprintf(cfd, "OK\n");

    } else if (strcmp(tok, "stats") == 0) {
        dump_stats_json(sts_fd, reply, sizeof(reply));
        dprintf(cfd, "%s", reply);

    } else if (strcmp(tok, "reload") == 0) {
        g_should_reload = 1;
        if (g_wake_fd >= 0) { __u64 one = 1; (void)write(g_wake_fd, &one, 8); }
        dprintf(cfd, "OK\n");

    } else if (strcmp(tok, "config") == 0) {
        char *verb = strtok(NULL, " \t\r\n");
        char *k    = strtok(NULL, " \t\r\n");
        char *v    = strtok(NULL, " \t\r\n");
        if (!verb || strcmp(verb, "set") || !k || !v) {
            dprintf(cfd, "ERR usage: config set <key> <val>\n"); return 0;
        }
        pthread_mutex_lock(&g_map_lock);
        int err = config_set(cfg_fd, k, v);
        pthread_mutex_unlock(&g_map_lock);
        if (err) dprintf(cfd, "ERR unknown key or bad value\n");
        else     dprintf(cfd, "OK\n");

    } else {
        dprintf(cfd, "ERR unknown command\n");
    }
    return 0;
}

static void *ctl_thread(void *arg)
{
    int lfd = (int)(long)arg;
    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            if (g_should_exit) break;
            logmsg("WARN", "accept: %s", strerror(errno));
            continue;
        }
        char buf[512];
        ssize_t n = read(cfd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = 0;
            handle_cmd(cfd, buf);
        }
        close(cfd);
    }
    return NULL;
}

static int open_ctl_socket(void)
{
    unlink(SOCK_PATH);
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { logmsg("ERROR", "socket: %s", strerror(errno)); return -1; }

    struct sockaddr_un sa = { .sun_family = AF_UNIX };
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", SOCK_PATH);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa))) {
        logmsg("ERROR", "bind %s: %s", SOCK_PATH, strerror(errno));
        close(fd); return -1;
    }
    chmod(SOCK_PATH, 0660);
    if (listen(fd, 16)) {
        logmsg("ERROR", "listen: %s", strerror(errno));
        close(fd); return -1;
    }
    return fd;
}

/* --------------------------------------------------------------------- */
/* Reload — diff-based reapplication of blocklist.txt                     */
/* --------------------------------------------------------------------- */
static int reload_blocklist(void)
{
    int fd = bpf_map__fd(g_skel->maps.blocklist);

    pthread_mutex_lock(&g_map_lock);

    /* Clear map in full (simple + correct). At 500K entries this is
     * <50 ms; acceptable for an infrequent operational event. A diff-
     * based reload would preserve runtime-added entries — see README. */
    __u32 key = 0, next;
    while (bpf_map_get_next_key(fd, key ? &key : NULL, &next) == 0) {
        bpf_map_delete_elem(fd, &next);
        key = next;
    }

    size_t inserted = 0;
    int err = load_blocklist_file(fd, BLOCKLIST_PATH, &inserted);
    pthread_mutex_unlock(&g_map_lock);

    logmsg("INFO", "blocklist reloaded: %zu entries", inserted);
    return err;
}

/* --------------------------------------------------------------------- */
/* Signal plumbing                                                        */
/* --------------------------------------------------------------------- */
static void on_signal(int sig)
{
    if (sig == SIGHUP)      g_should_reload = 1;
    else                    g_should_exit   = 1;
    if (g_wake_fd >= 0) { __u64 one = 1; (void)write(g_wake_fd, &one, 8); }
}

/* --------------------------------------------------------------------- */
/* main                                                                   */
/* --------------------------------------------------------------------- */
static int libbpf_print_fn(enum libbpf_print_level lvl, const char *fmt,
                           va_list ap)
{
    if (lvl == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, fmt, ap);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <ifname>\n", argv[0]);
        return 1;
    }
    snprintf(g_ifname, sizeof(g_ifname), "%s", argv[1]);
    g_ifindex = if_nametoindex(g_ifname);
    if (!g_ifindex) {
        logmsg("ERROR", "if_nametoindex(%s): %s", g_ifname, strerror(errno));
        return 1;
    }

    libbpf_set_print(libbpf_print_fn);
    bump_memlock();

    /* 0. ensure runtime directories exist                               */
    ensure_dir("/sys/fs/bpf",  0755);
    ensure_dir(PIN_DIR,        0755);
    ensure_dir(LOG_DIR,        0750);
    ensure_dir("/etc/ddos",    0755);

    /* 1. open → load → (pin) → attach                                   */
    g_skel = xdp_ddos_bpf__open();
    if (!g_skel) {
        logmsg("ERROR", "skel open: %s", strerror(errno));
        return 1;
    }

    if (xdp_ddos_bpf__load(g_skel)) {
        logmsg("ERROR", "skel load (verifier?): %s", strerror(errno));
        xdp_ddos_bpf__destroy(g_skel);
        return 1;
    }

    if (pin_maps(g_skel)) {
        xdp_ddos_bpf__destroy(g_skel);
        return 1;
    }

    if (attach_xdp(g_skel, g_ifindex, &g_xdp_flags)) {
        xdp_ddos_bpf__destroy(g_skel);
        return 1;
    }

    /* 2. seed blocklist                                                 */
    size_t seeded = 0;
    load_blocklist_file(bpf_map__fd(g_skel->maps.blocklist),
                        BLOCKLIST_PATH, &seeded);
    logmsg("INFO", "blocklist loaded: %zu entries", seeded);

    /* 3. perf buffer + control socket + signals                         */
    struct perf_buffer *pb = perf_buffer__new(
        bpf_map__fd(g_skel->maps.events),
        /* page_cnt */ 64,
        on_drop_event, on_drop_lost, NULL, NULL);
    if (!pb) {
        logmsg("ERROR", "perf_buffer__new: %s", strerror(errno));
        goto out;
    }

    g_wake_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);

    int lfd = open_ctl_socket();
    pthread_t ctl_tid = 0;
    if (lfd >= 0) pthread_create(&ctl_tid, NULL, ctl_thread,
                                 (void *)(long)lfd);

    struct sigaction sa = { .sa_handler = on_signal };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    logmsg("INFO", "running on %s (ifindex=%d, flags=0x%x)",
           g_ifname, g_ifindex, g_xdp_flags);

    /* 4. main loop                                                      */
    while (!g_should_exit) {
        if (g_should_reload) {
            g_should_reload = 0;
            reload_blocklist();
        }

        int err = perf_buffer__poll(pb, 100 /* ms */);
        if (err == -EINTR) continue;
        if (err < 0) {
            logmsg("WARN", "perf poll: %s", strerror(-err));
            usleep(10000);
        }

        if (g_wake_fd >= 0) {
            __u64 drain;
            while (read(g_wake_fd, &drain, 8) > 0) { /* drain */ }
        }
    }

    logmsg("INFO", "shutting down");

    if (lfd >= 0) {
        shutdown(lfd, SHUT_RDWR);
        close(lfd);
        unlink(SOCK_PATH);
    }
    if (ctl_tid) pthread_join(ctl_tid, NULL);

    perf_buffer__free(pb);

out:
    /* detach & unpin                                                    */
    bpf_xdp_detach(g_ifindex, g_xdp_flags, NULL);

    {
        const char *names[] = {
            "rate_counters","conn_tracker","blocklist","allowlist",
            "stats","config_map","events","event_ratelimit"
        };
        for (size_t i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
            char p[256]; snprintf(p, sizeof(p), PIN_DIR "/%s", names[i]);
            unlink(p);
        }
        rmdir(PIN_DIR);
    }

    xdp_ddos_bpf__destroy(g_skel);
    if (g_wake_fd >= 0) close(g_wake_fd);
    return 0;
}
