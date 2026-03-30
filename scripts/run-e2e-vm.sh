#!/usr/bin/env bash
# Run E2E tests inside a local LVH (little-vm-helper) QEMU VM.
#
# Environment variables:
#   LVH_KERNEL   kernel version tag  (default: 6.6-main)
#   LVH_SSH_PORT host SSH port        (default: 2222)
#   LVH_TIMEOUT  test timeout in sec  (default: 300)
#   LVH_DATA     image cache dir      (default: ~/.cache/lvh)
set -euo pipefail

KERNEL="${LVH_KERNEL:-6.6-main}"
SSH_PORT="${LVH_SSH_PORT:-2222}"
TIMEOUT="${LVH_TIMEOUT:-300}"
LVH_DATA="${LVH_DATA:-${HOME}/.cache/lvh}"
WORKDIR="$(cd "$(dirname "$0")/.." && pwd)"
CONSOLE_LOG="/tmp/lvh-${KERNEL//\//-}.log"

ssh_opts=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o LogLevel=ERROR -o ConnectTimeout=5 -p "$SSH_PORT")

run_ssh() {
    sshpass -p '' ssh "${ssh_opts[@]}" root@localhost "$@"
}

# ── cleanup ────────────────────────────────────────────────────────────────────
cleanup() {
    echo ""
    echo "==> Shutting down VM..."
    run_ssh poweroff 2>/dev/null || true
    sleep 2
    # Force-kill any surviving QEMU process that has our kernel tag in its args
    pkill -f "qemu.*${KERNEL}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ── preflight ──────────────────────────────────────────────────────────────────
for cmd in lvh qemu-system-x86_64 sshpass; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: '$cmd' not found. Run: make devsetup" >&2
        exit 1
    fi
done

if [ ! -x "$WORKDIR/tests/e2e/e2e.test" ]; then
    echo "ERROR: tests/e2e/e2e.test not found. Run: make testbin-e2e" >&2
    exit 1
fi

if [ -c /dev/kvm ]; then
    echo "==> KVM available — hardware acceleration enabled"
else
    echo "WARNING: /dev/kvm not available — running without KVM (will be slow)"
fi

# ── boot ───────────────────────────────────────────────────────────────────────
mkdir -p "$LVH_DATA"
echo "==> Starting LVH VM (kernel: ${KERNEL})..."
echo "    image cache: ${LVH_DATA}"
echo "    console log: ${CONSOLE_LOG}"

lvh run \
    --image "quay.io/lvh-images/kind:${KERNEL}" \
    --pull-image \
    --host-mount "${WORKDIR}" \
    --daemonize \
    --port "${SSH_PORT}:22" \
    --dir "${LVH_DATA}" \
    --console-log-file "${CONSOLE_LOG}"

# ── wait for SSH ───────────────────────────────────────────────────────────────
echo "==> Waiting for VM SSH (up to 120s)..."
for i in $(seq 1 120); do
    if run_ssh true 2>/dev/null; then
        echo "    SSH ready (${i}s)"
        break
    fi
    if [ "$i" -eq 120 ]; then
        echo "ERROR: SSH not available after 120s. Console log:" >&2
        cat "$CONSOLE_LOG" >&2
        exit 1
    fi
    sleep 1
done

echo "    Kernel in VM: $(run_ssh uname -r)"

# ── run tests ─────────────────────────────────────────────────────────────────
# Brief pause to let sshd stabilise after the kernel-version probe.
sleep 2
echo "==> Running E2E tests..."
for attempt in 1 2 3; do
    run_ssh "cd /host && ./tests/e2e/e2e.test -test.v -test.count=1 -test.timeout=${TIMEOUT}s"
    rc=$?
    # rc=255 means SSH connection failure — retry; any other rc is a test result, propagate it
    [ $rc -ne 255 ] && exit $rc
    if [ $attempt -lt 3 ]; then
        echo "    SSH connection failed (attempt $attempt), retrying in 3s..."
        sleep 3
    else
        exit $rc
    fi
done
