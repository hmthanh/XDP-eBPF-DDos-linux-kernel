# XDP/eBPF DDoS Defence — L4 filter for 200 M-MAU WebSocket chat

Production-grade XDP/eBPF DDoS and connection-scaling stack for a real-time
chat platform behind Erlang/BEAM. Targets **Ubuntu 24.04 LTS, kernel 6.8
(HWE), libbpf ≥ 1.3, clang-17+**. Deployable by a single engineer on a
fresh host in under 30 minutes.

---

## 1. Architecture

```
                  ┌──────────────────────────────────────────────┐
                  │ Client traffic (WebSocket, TLS, UDP media)   │
                  └───────────────────┬──────────────────────────┘
                                      │
                                      ▼
                            ┌───────────────────┐
                            │  NIC (CX-6 / E810)│   SR-IOV, native XDP
                            └─────────┬─────────┘
                                      │
                  ╔═══════════════════▼═══════════════════════╗
                  ║  XDP fast-path  (xdp_ddos_kern.c)         ║
                  ║  ───────────────────────────────────────  ║
                  ║  allowlist? → PASS                        ║
                  ║  blocklist? → DROP                        ║
                  ║  fragment?  → DROP  (STAT_DROP_FRAG)      ║
                  ║  uRPF fail? → DROP  (STAT_DROP_SPOOF)     ║
                  ║  SYN flood? → DROP  (STAT_DROP_SYN)       ║
                  ║  UDP amp?   → DROP  (STAT_DROP_UDP_AMP)   ║
                  ║  ICMP rate? → DROP  (STAT_DROP_ICMP)      ║
                  ║  PPS rate?  → DROP  (STAT_DROP_RATE)      ║
                  ║  otherwise  → PASS                        ║
                  ╚═══════════════════╤═══════════════════════╝
                                      │ (XDP_PASS)
                                      ▼
                  ╔══════════════════════════════════════════╗
                  ║  TC ingress via ifb0                     ║
                  ║  tc_ingress_kern.o:                      ║
                  ║    per-src-IP token bucket (200 Mbit/s)  ║
                  ╚═══════════════════╤══════════════════════╝
                                      │
                                      ▼
                         ┌────────────────────────┐
                         │ Kernel TCP/UDP stack   │  (tuned via
                         │ (BBR, FQ, syncookies)  │   sysctl_discord.conf)
                         └──────────┬─────────────┘
                                    │ epoll / (future) io_uring
                                    ▼
                         ┌────────────────────────┐
                         │ BEAM WebSocket layer   │  10 M+ connections
                         │ → Erlang processes     │
                         └──────────┬─────────────┘
                                    │  egress
                                    ▼
                  ╔══════════════════════════════════════════╗
                  ║  FQ root qdisc (BBR pacing)              ║
                  ║  clsact egress:                          ║
                  ║    tc_egress_kern.o                      ║
                  ║    per-dst-IP token bucket (100 Mbit/s)  ║
                  ╚═══════════════════╤══════════════════════╝
                                      │
                                      ▼
                            ┌───────────────────┐
                            │       NIC         │
                            └───────────────────┘
```

No iptables / nftables / Netfilter are in any hot path.

---

## 2. Prerequisites

### Packages

```bash
sudo apt update
sudo apt install -y \
    clang-17 llvm-17 libbpf-dev \
    linux-tools-$(uname -r) bpftool \
    linux-headers-$(uname -r) \
    iproute2 libelf-dev zlib1g-dev \
    build-essential
```

### Kernel / NIC sanity checks

```bash
# Kernel 6.8+:
uname -r
# Expected: 6.8.x-generic (HWE)

# BTF available (required for CO-RE):
ls -l /sys/kernel/btf/vmlinux
# Expected: a readable file

# NIC driver supports native XDP:
ethtool -i eth0 | grep driver
# Known good drivers: mlx5_core, ice, i40e, ixgbe (partial), bnxt, virtio_net (6.x+)

# Verify native-mode feature bit (advisory — actual support is confirmed at attach):
ethtool -i eth0
```

### Dedicated user

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin ddos-user
sudo mkdir -p /etc/ddos /var/log/ddos
sudo chown ddos-user:ddos-user /var/log/ddos
```

---

## 3. Build & deploy

```bash
# 1. Clone / unpack into /opt/xdp-ddos
cd /opt/xdp-ddos

# 2. Build (creates vmlinux.h, xdp_ddos.skel.h, *.o, xdp_ddos_user)
sudo make

# 3. Apply kernel tuning
sudo cp sysctl_discord.conf /etc/sysctl.d/99-discord-chat.conf
sudo sysctl --system

# 4. Install binaries & systemd unit
sudo make install

# 5. Adjust the interface name in the unit if not eth0
sudo sed -i 's/eth0/ens2f0/g' /etc/systemd/system/ddos-defence.service
sudo systemctl daemon-reload

# 6. Seed the blocklist (optional)
sudo install -m 0644 etc/ddos/blocklist.txt /etc/ddos/blocklist.txt

# 7. Enable and start
sudo systemctl enable --now ddos-defence

# 8. Verify
sudo make check
sudo journalctl -u ddos-defence -n 50 --no-pager
```

Expected output from `make check`:

```
=== bpftool prog show ===
NN: xdp  name xdp_ddos  tag ...
=== bpftool map show ===
rate_counters  type lru_hash  max_entries 2000000  ...
conn_tracker   type lru_hash  max_entries 4000000  ...
blocklist      type hash      max_entries 500000   ...
... etc
```

---

## 4. Runtime management

### Control socket (`/run/ddos.sock`, `SOCK_STREAM`)

```bash
# Block an IP for 3600 seconds
echo "block 1.2.3.4 3600" | sudo nc -U /run/ddos.sock
# → OK

# Permanent block (no seconds argument)
echo "block 203.0.113.9" | sudo nc -U /run/ddos.sock

# Unblock
echo "unblock 1.2.3.4" | sudo nc -U /run/ddos.sock

# Dump all counters as JSON
echo "stats" | sudo nc -U /run/ddos.sock
# → {"pass":51234567,"drop_blocklist":12,"drop_rate":3451, ...}

# Reload /etc/ddos/blocklist.txt (same as SIGHUP)
echo "reload" | sudo nc -U /run/ddos.sock

# Hot-tune a threshold — no program reattach required
echo "config set pps_limit 20000"        | sudo nc -U /run/ddos.sock
echo "config set syn_threshold 128"      | sudo nc -U /run/ddos.sock
echo "config set udp_amp_threshold 1024" | sudo nc -U /run/ddos.sock
echo "config set icmp_pps_limit 50"      | sudo nc -U /run/ddos.sock
```

### Signals

```bash
sudo systemctl reload ddos-defence   # SIGHUP → reload blocklist.txt
sudo systemctl restart ddos-defence  # full reload including program
sudo systemctl stop ddos-defence     # detach XDP + unpin maps
```

### JSON drop events

`stdout` of `xdp_ddos_user` (captured by journald):

```json
{ "ts": "2026-04-24T09:12:34.123Z", "src_ip": "1.2.3.4", "dport": 443, "reason": "SYN_FLOOD", "action": "DROP" }
```

Only the _first_ drop from a given source IP within a 1-second window
is emitted — this prevents a flood of millions of events per second
from drowning the logging pipeline.

---

## 5. Tuning guide

### Per-IP PPS threshold

Default 10 000 pps. Dial up during product events with heavy per-user
reconnect churn; dial down during active attacks.

```bash
echo "config set pps_limit 15000" | sudo nc -U /run/ddos.sock
```

No reattach happens — writes land in the `config_map` and are picked up
by the next packet.

### Switching from DRV to SKB mode

The daemon auto-detects lack of native-XDP support and falls back to SKB
mode with a warning. Performance implications:

| Mode          | Drop rate (single core, 25 GbE) | CPU overhead @ 10 Mpps |
| ------------- | ------------------------------- | ---------------------- |
| DRV (native)  | **20–50 Mpps**                  | < 15 %                 |
| SKB (generic) | 3–5 Mpps                        | 60–80 %                |

If you see "NIC does not support native XDP" in the journal, fix the
driver or replace the NIC — SKB mode will saturate CPU before the line.

### io_uring integration path

BEAM currently uses epoll; `kernel.io_uring_disabled = 0` is set so
Rust sidecar services (media relay, rate-limit aggregator) can use
io_uring for zero-copy UDP recv. Wiring BEAM itself to io_uring is
tracked as a separate workstream (`+K true`-style BEAM emulator flag).

### LPM_TRIE upgrade for wide CIDR blocklists

The current `blocklist` uses `BPF_MAP_TYPE_HASH` keyed on 32-bit IPs.
CIDRs wider than `/20` are logged and inserted only as the network
address. For wide blocks (e.g. country-level), migrate the map to
`BPF_MAP_TYPE_LPM_TRIE` — tracked, not a code stub. The hot-path change
is one `bpf_map_lookup_elem` call with a `struct bpf_lpm_trie_key`.

---

## 6. Performance expectations

| Metric                                 | Native XDP (DRV) | SKB fallback |
| -------------------------------------- | ---------------- | ------------ |
| Single-core drop rate, 25 GbE          | 20–50 Mpps       | 3–5 Mpps     |
| 32-core drop rate (linear)             | 400+ Mpps        | ~70 Mpps     |
| CPU overhead @ 10 Mpps                 | < 15 % of 1 core | 60–80 %      |
| Added latency per pass                 | 40–80 ns         | 1–3 µs       |
| Locked kernel memory (2 M LRU entries) | ~180 MB          | same         |

Memory breakdown (BPF_F_NO_PREALLOC on LRU):

- `rate_counters` 2 M × ~80 B = 160 MB
- `conn_tracker` 4 M × ~64 B = 256 MB (peak; LRU evicts idle flows)
- `blocklist` 500 K × ~24 B = 12 MB
- `stats` percpu, negligible

Total: ~430 MB locked at peak. Size the host with ≥ 1 GB above BEAM's
working set to absorb this.

---

## 7. Troubleshooting

### XDP attach fails with `EOPNOTSUPP` / `ENOTSUP`

→ The driver does not support native mode. The daemon logs
"NIC does not support native XDP, using SKB mode" and continues. To
regain native mode, update the driver (`ethtool -i <nic>` → check
`driver`) or fall back to a supported NIC.

### Map creation fails with `ENOMEM`

→ Check `ulimit -l` (locked memory) — it should be `unlimited` for the
running user. The systemd unit sets `LimitMEMLOCK=infinity`; verify
with `systemctl show ddos-defence -p LimitMEMLOCK`. If running manually,
export `LC_ALL` and use `sudo` or `prlimit --memlock=unlimited:unlimited`.

### `bpftool prog show` returns empty

→ The daemon either failed to attach or is running with insufficient
capabilities. Verify:

```bash
sudo journalctl -u ddos-defence | grep -E 'load|attach|capability'
sudo getcap /usr/local/sbin/xdp_ddos_user
```

Systemd unit should show `CapabilityBoundingSet` including `CAP_BPF`
and `CAP_PERFMON`.

### Verifier rejection at load time

→ Nearly always a clang/kernel mismatch. Ensure `clang-17`:

```bash
clang-17 --version    # should print 17.x
which clang-17
```

If you are on clang-14, rebuild: `make clean && CLANG=clang-17 make`.

### High `STAT_DROP_RATE` on legitimate traffic

→ The default 10 k pps threshold is conservative for server-to-server
links. Raise it:

```bash
echo "config set pps_limit 50000" | sudo nc -U /run/ddos.sock
```

Then add the server IP to the allowlist to bypass all checks:

```bash
sudo bpftool map update pinned /sys/fs/bpf/ddos/allowlist \
    key hex  0a 00 00 05  value hex  01
```

### `tc_rate_limit.sh` fails at `ip link add ifb0`

→ `ifb` module not loaded. The script runs `modprobe ifb` implicitly but
on very minimal installs you may need `apt install linux-modules-extra-$(uname -r)`.

### XDP program still attached after `systemctl stop`

→ Run `ip link set dev eth0 xdp off` manually. The `ExecStopPost` in the
unit covers this during normal exit, but it does not run if the unit is
masked or the machine kernel-panicked. Add a `@reboot` check-script in
production if you want belt-and-braces.

---

## License

![LICENSE](https://img.shields.io/github/license/discord/xdp-ebpf-ddos-linux-kernel)