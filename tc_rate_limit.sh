#!/usr/bin/env bash
# tc_rate_limit.sh — configure TC qdiscs and attach eBPF rate limiters.
#
# Idempotent: safe to run repeatedly. Always teardown-first, then rebuild.
#
# Topology applied:
#
#   ingress path:  NIC ── (clsact:ingress, mirred → ifb0) ── ifb0:root HTB + tc_ingress
#   egress path:   stack ── FQ (BBR-compatible) + tc_egress on NIC
#
# Default caps (override via ing_config / egr_config maps after load):
#   - per src-IP ingress: 200 Mbit/s
#   - per dst-IP egress : 100 Mbit/s

set -euo pipefail

NIC="${NIC:-eth0}"
IFB="${IFB:-ifb0}"
BPF_OBJ_DIR="${BPF_OBJ_DIR:-/usr/local/lib}"
TC_ING_OBJ="${BPF_OBJ_DIR}/tc_ingress_kern.o"
TC_EGR_OBJ="${BPF_OBJ_DIR}/tc_egress_kern.o"

# Fall back to the current working dir during first-time dev / manual runs
for f in "$TC_ING_OBJ" "$TC_EGR_OBJ"; do
    if [[ ! -f "$f" ]]; then
        alt="$(pwd)/$(basename "$f")"
        if [[ -f "$alt" ]]; then
            case "$f" in
                "$TC_ING_OBJ") TC_ING_OBJ="$alt" ;;
                "$TC_EGR_OBJ") TC_EGR_OBJ="$alt" ;;
            esac
        else
            echo "ERROR: $f not found (run 'make tc-bpf' first)" >&2
            exit 1
        fi
    fi
done

log() { printf '[tc_rate_limit] %s\n' "$*" >&2; }

# ---------- 1. teardown ----------------------------------------------------
log "tearing down previous qdiscs on ${NIC} and ${IFB} (if any)"
tc qdisc del dev "${NIC}" root    2>/dev/null || true
tc qdisc del dev "${NIC}" clsact  2>/dev/null || true
tc qdisc del dev "${IFB}" root    2>/dev/null || true
ip link set dev "${IFB}" down     2>/dev/null || true
ip link del dev "${IFB}"          2>/dev/null || true

# ---------- 2. egress FQ root qdisc ----------------------------------------
# FQ is required for BBR (see sysctl_discord.conf).
# flow_limit 200 : cap per-flow backlog at 200 packets — prevents any single
#                  greedy flow from monopolising queue memory when millions
#                  of WebSocket connections share a NIC.
# quantum 3028   : ≈ 2 × TCP MSS (1514 bytes). Lower quantum improves
#                  fairness for small-packet chat traffic at the cost of
#                  slightly higher scheduler overhead — the right trade-off
#                  for a chat workload dominated by sub-1 KB frames.
log "adding FQ root qdisc on ${NIC} (required for BBR)"
tc qdisc add dev "${NIC}" root handle 1: fq flow_limit 200 quantum 3028

# ---------- 3. egress eBPF classifier (per-dst-IP token bucket) ------------
log "attaching clsact egress filter on ${NIC}"
tc qdisc add dev "${NIC}" clsact
tc filter add dev "${NIC}" egress bpf direct-action obj "${TC_EGR_OBJ}" sec tc

# ---------- 4. ingress mirror via ifb0 ------------------------------------
# ifb0 exposes the ingress path as an egress qdiscable device so we can run
# a full HTB + eBPF pipeline against it (vanilla ingress can only police,
# not shape).
log "creating ${IFB} and mirroring ingress"
modprobe ifb numifbs=1 2>/dev/null || true
ip link add "${IFB}" type ifb 2>/dev/null || true
ip link set dev "${IFB}" up

tc qdisc add dev "${NIC}" handle ffff: ingress
tc filter add dev "${NIC}" parent ffff: protocol ip u32 match u32 0 0 \
    action mirred egress redirect dev "${IFB}"

# ---------- 5. ingress shaping on ifb0 ------------------------------------
# HTB gives us a hard aggregate ceiling; the eBPF filter enforces per-IP.
# rate 10gbit ceil 10gbit is a no-op ceiling on modern NICs; adjust as
# needed for your uplink. The meaningful policing is in tc_ingress_kern.o.
log "installing HTB + per-IP token-bucket BPF on ${IFB}"
tc qdisc add dev "${IFB}" root handle 1: htb default 10
tc class add dev "${IFB}" parent 1: classid 1:1  htb rate 10gbit ceil 10gbit
tc class add dev "${IFB}" parent 1:1 classid 1:10 htb rate 9gbit  ceil 10gbit
tc filter add dev "${IFB}" parent 1: bpf direct-action obj "${TC_ING_OBJ}" sec tc

# ---------- 6. report ------------------------------------------------------
log "final state:"
tc -s qdisc show dev "${NIC}"
echo
tc -s qdisc show dev "${IFB}"
echo
tc -s filter show dev "${NIC}" egress
echo
tc -s filter show dev "${IFB}"
