#!/usr/bin/env bash
set -euo pipefail

echo "==> Cleaning up unused apt repos..."
# The base devcontainer image ships a Yarn repo whose GPG key rotates
# frequently, breaking apt-get update. This project doesn't use Yarn,
# so remove the source to avoid the issue entirely.
rm -f /etc/apt/sources.list.d/yarn.list

echo "==> Installing eBPF toolchain..."
apt-get update -qq
apt-get install -y --no-install-recommends \
  clang \
  llvm \
  linux-headers-generic \
  linux-tools-generic \
  libbpf-dev \
  make \
  jq \
  iproute2 \
  2>/dev/null

# Symlink bpftool from the kernel-matched linux-tools package
BPFTOOL=$(find /usr/lib/linux-tools* -name bpftool 2>/dev/null | head -1 || true)
if [ -n "$BPFTOOL" ]; then
  ln -sf "$BPFTOOL" /usr/local/bin/bpftool
  echo "==> bpftool linked from $BPFTOOL"
else
  echo "WARNING: bpftool not found via linux-tools. Install manually if needed."
fi

echo "==> Installing VM testing tools (QEMU, sshpass, Docker CLI)..."
apt-get install -y --no-install-recommends qemu-system-x86 sshpass docker.io
# Allow the dev user to talk to the Docker socket without sudo
usermod -aG docker vscode 2>/dev/null || true

echo "==> Installing Go tools..."
go install github.com/cilium/ebpf/cmd/bpf2go@latest
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
GOTOOLCHAIN=auto go install github.com/cilium/little-vm-helper/cmd/lvh@v0.0.28

echo "==> Running go mod tidy..."
cd /workspaces/Leashd
go mod tidy 2>/dev/null || true

echo "==> Generating vmlinux.h from host kernel BTF..."
mkdir -p ebpf/headers
if [ -f /sys/kernel/btf/vmlinux ]; then
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/headers/vmlinux.h
  echo "    vmlinux.h generated ($(wc -l < ebpf/headers/vmlinux.h) lines)"
else
  echo "    WARNING: /sys/kernel/btf/vmlinux not found."
  echo "    Run 'make vmlinux' manually after ensuring BTF is available."
fi

echo ""
echo "leashd dev environment ready."
echo "  make build      - build the leashd binary"
echo "  make test       - run unit tests (no root required)"
echo "  sudo make test-int      - run integration tests"
echo "  sudo make test-e2e      - run end-to-end tests (skips in devcontainer)"
echo "  make test-e2e-vm        - run e2e tests in a local LVH VM (requires KVM)"
