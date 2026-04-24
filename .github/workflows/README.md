# GitHub Actions Workflows for XDP/eBPF DDoS Defence

This directory contains automated CI/CD workflows for building and validating the XDP/eBPF DDoS defence project.

## Workflows

### 1. `build.yml` — Main Build Pipeline

**Triggers**: Push to `main`/`develop` branches, pull requests to `main`

**Steps**:

- Updates package cache
- Installs build dependencies (clang-17, llvm-17, libbpf-dev, bpftool, linux-headers, libelf-dev, zlib1g-dev)
- Verifies kernel BTF support (`/sys/kernel/btf/vmlinux`)
- Runs `make clean && make all` to build all artifacts
- Lists generated binaries and objects
- Uploads build artifacts for 30 days
- Creates GitHub release on git tag push

**Artifacts**:

- `xdp_ddos_user` — userspace daemon
- `xdp_ddos_kern.o` — kernel XDP program
- `tc_ingress_kern.o` — ingress traffic control eBPF program
- `tc_egress_kern.o` — egress traffic control eBPF program
- `xdp_ddos.skel.h` — libbpf skeleton header
- `vmlinux.h` — kernel BTF type definitions

### 2. `lint.yml` — Code Quality Checks

**Triggers**: Push to `main`/`develop` branches, pull requests to `main`

**Steps**:

- Checks C code formatting with `clang-format`
- Validates shell script syntax with `shellcheck` (tc_rate_limit.sh)
- Verifies Makefile syntax
- Runs clang static analyzer on C sources

## Environment Requirements

The workflows are optimized for:

- **OS**: Ubuntu 24.04 LTS (matches project requirements)
- **Kernel**: 6.8+ with `CONFIG_DEBUG_INFO_BTF=y`
- **Toolchain**: clang-17, llvm-17, gcc, build-essential

## Limitations & Notes

1. **Kernel BTF Support**: The build requires `/sys/kernel/btf/vmlinux` to be present. GitHub Actions Ubuntu 24.04 runners should have this by default, but if the build fails, you may need to:
   - Use a custom runner on a machine with kernel 6.8+
   - Use a container with proper kernel headers

2. **Testing**: The current workflows do not include runtime testing (which would require kernel module loading privileges). For full validation, test on a target Ubuntu 24.04 LTS machine.

3. **Release Automation**: Workflows automatically create GitHub releases when you push a git tag (e.g., `git tag v1.0.0 && git push --tags`).

## Local Testing

To test the workflows locally, install act:

```bash
brew install act  # macOS
# or: sudo apt-get install -y act  # Linux

# Run the build workflow
act -j build

# Run the lint workflow
act -j lint
```

## Customization

To modify the workflows:

1. Edit `.github/workflows/build.yml` or `.github/workflows/lint.yml`
2. Commit and push — workflows will trigger automatically
3. Monitor in the GitHub Actions tab of your repository
