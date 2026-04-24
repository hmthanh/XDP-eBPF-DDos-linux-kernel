# XDP/eBPF DDoS defence build system
# Target: Ubuntu 24.04 LTS, kernel 6.8 (HWE), libbpf ≥ 1.3, clang-17+
#
# Usage:
#   make                 # build everything
#   make load NIC=eth0   # build + attach to NIC
#   make unload NIC=eth0 # detach and unpin maps
#   make check           # post-load sanity via bpftool
#   make clean           # remove generated artefacts

CLANG         ?= clang-17
LLC           ?= llc-17
BPFTOOL       ?= bpftool
NIC           ?= eth0

ARCH          := $(shell uname -m)
INCLUDE_ARCH  := /usr/include/$(ARCH)-linux-gnu

KERN_SRC      := xdp_ddos_kern.c
KERN_OBJ      := xdp_ddos_kern.o
SKEL          := xdp_ddos.skel.h

TC_ING_SRC    := tc_ingress_kern.c
TC_ING_OBJ    := tc_ingress_kern.o
TC_EGR_SRC    := tc_egress_kern.c
TC_EGR_OBJ    := tc_egress_kern.o

USER_SRC      := xdp_ddos_user.c
USER_BIN      := xdp_ddos_user

BPF_CFLAGS    := -O2 -g -Wall \
                 -target bpf \
                 -D__TARGET_ARCH_$(ARCH) \
                 -I. -I$(INCLUDE_ARCH) \
                 -Wno-unused-value \
                 -Wno-pointer-sign \
                 -Wno-compare-distinct-pointer-types

USER_CFLAGS   := -O2 -Wall -Wextra -Wno-unused-parameter \
                 -I. -I$(INCLUDE_ARCH)
USER_LDLIBS   := -lbpf -lelf -lz -lpthread

.PHONY: all vmlinux kern skeleton user tc-bpf load unload clean check install

all: vmlinux kern skeleton user tc-bpf

vmlinux: vmlinux.h
vmlinux.h:
	@test -f /sys/kernel/btf/vmlinux || { \
	    echo "ERROR: /sys/kernel/btf/vmlinux missing — need CONFIG_DEBUG_INFO_BTF=y"; \
	    exit 1; }
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

kern: $(KERN_OBJ)
$(KERN_OBJ): $(KERN_SRC) vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $(KERN_SRC) -o $(KERN_OBJ)

skeleton: $(SKEL)
$(SKEL): $(KERN_OBJ)
	$(BPFTOOL) gen skeleton $(KERN_OBJ) > $(SKEL)

tc-bpf: $(TC_ING_OBJ) $(TC_EGR_OBJ)
$(TC_ING_OBJ): $(TC_ING_SRC) vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $(TC_ING_SRC) -o $(TC_ING_OBJ)
$(TC_EGR_OBJ): $(TC_EGR_SRC) vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $(TC_EGR_SRC) -o $(TC_EGR_OBJ)

user: $(USER_BIN)
$(USER_BIN): $(USER_SRC) $(SKEL)
	gcc $(USER_CFLAGS) $(USER_SRC) -o $(USER_BIN) $(USER_LDLIBS)

load: all
	-ip link set dev $(NIC) xdp off 2>/dev/null
	sudo ./$(USER_BIN) $(NIC)

unload:
	-ip link set dev $(NIC) xdp off
	-tc qdisc del dev $(NIC) root 2>/dev/null
	-tc qdisc del dev $(NIC) clsact 2>/dev/null
	-tc qdisc del dev ifb0 root 2>/dev/null
	-ip link del dev ifb0 type ifb 2>/dev/null
	-rm -rf /sys/fs/bpf/ddos
	-rm -rf /sys/fs/bpf/tc/globals/ingress_tb /sys/fs/bpf/tc/globals/egress_tb

check:
	@echo "=== bpftool prog show ==="
	$(BPFTOOL) prog show
	@echo
	@echo "=== bpftool map show ==="
	$(BPFTOOL) map show
	@echo
	@echo "=== XDP status on $(NIC) ==="
	ip -d link show dev $(NIC) | grep -E 'xdp|prog'

install: all
	install -d /usr/local/sbin /usr/local/bin /etc/ddos
	install -m 0755 $(USER_BIN)         /usr/local/sbin/
	install -m 0755 tc_rate_limit.sh    /usr/local/bin/
	install -m 0644 $(TC_ING_OBJ)       /usr/local/lib/
	install -m 0644 $(TC_EGR_OBJ)       /usr/local/lib/
	install -m 0644 sysctl_discord.conf /etc/sysctl.d/99-discord-chat.conf
	install -m 0644 systemd/ddos-defence.service /etc/systemd/system/
	@test -f /etc/ddos/blocklist.txt || echo "# one CIDR or IP per line" > /etc/ddos/blocklist.txt
	@echo "install complete — run 'systemctl daemon-reload && systemctl enable --now ddos-defence'"

clean:
	rm -f *.o $(USER_BIN) $(SKEL) vmlinux.h
