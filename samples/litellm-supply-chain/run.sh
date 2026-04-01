#!/usr/bin/env bash
# run.sh — self-contained setup + execution for the LiteLLM supply-chain demo.
#
# What this script does:
#   1. Installs leashd binary (builds from source if not present)
#   2. Creates a Python venv and installs litellm 1.82.8 (the compromised version)
#   3. Runs the demo app under leashd enforcement
#
# Requirements on the test VM:
#   • Linux kernel 5.8+  with CONFIG_DEBUG_INFO_BTF=y, cgroup v2
#   • go 1.21+, clang, llvm, libbpf-dev  (only if building leashd from source)
#   • python3, python3-venv
#   • sudo / root

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LEASHD_BIN="$REPO_ROOT/bin/leashd"
VENV_DIR="$SCRIPT_DIR/.venv"

RED="\033[31m"; YELLOW="\033[33m"; GREEN="\033[32m"; CYAN="\033[36m"; RESET="\033[0m"

info()  { echo -e "${CYAN}[setup]${RESET} $*"; }
ok()    { echo -e "${GREEN}[ok]${RESET}    $*"; }
warn()  { echo -e "${YELLOW}[warn]${RESET}  $*"; }
fatal() { echo -e "${RED}[error]${RESET} $*" >&2; exit 1; }

# ── 1. Ensure leashd binary ──────────────────────────────────────────────────

if [[ ! -x "$LEASHD_BIN" ]]; then
    info "leashd binary not found — building from source..."
    if ! command -v go &>/dev/null; then
        fatal "go is not installed. Install Go 1.21+ and try again."
    fi
    if ! command -v clang &>/dev/null; then
        fatal "clang is not installed. Run: apt-get install -y clang llvm libbpf-dev"
    fi
    (cd "$REPO_ROOT" && make build)
    ok "leashd built: $LEASHD_BIN"
else
    ok "leashd binary found: $LEASHD_BIN"
fi

# ── 2. Python venv + compromised litellm ────────────────────────────────────

if [[ ! -d "$VENV_DIR" ]]; then
    info "Creating Python venv at $VENV_DIR ..."
    python3 -m venv "$VENV_DIR"
fi

info "Installing dependencies (litellm==1.82.8 — the compromised version)..."
warn "litellm 1.82.8 contained malicious code that exfiltrated credentials."
warn "This VM is the intended test target. Do NOT run this on a real workstation."

# Install inside the venv — pip runs BEFORE leashd wraps the process, so
# pypi.org is reachable.  The malicious .pth payload triggers on the next
# Python start (step 3), which IS wrapped by leashd.
"$VENV_DIR/bin/pip" install --quiet -r "$SCRIPT_DIR/requirements.txt"
ok "Python dependencies installed."

# ── 3. Run demo under leashd ────────────────────────────────────────────────

info "Launching demo app under leashd enforcement..."
echo
echo "  Policy file : $SCRIPT_DIR/rules.yaml"
echo "  Default     : BLOCK (deny-all except explicit allows)"
echo "  Allowed     : pypi.org, api.openai.com, api.anthropic.com, loopback"
echo "  Blocked     : everything else (incl. models.litellm.cloud, checkmarx.zone)"
echo

# Check for root — leashd requires CAP_BPF / CAP_NET_ADMIN
if [[ $EUID -ne 0 ]]; then
    warn "Not running as root; re-executing with sudo..."
    exec sudo -E env PATH="$PATH" bash "$0" "$@"
fi

exec "$LEASHD_BIN" run \
    --dir "$SCRIPT_DIR" \
    -- \
    "$VENV_DIR/bin/python3" "$SCRIPT_DIR/app.py" "$@"
