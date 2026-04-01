#!/usr/bin/env bash
# run.sh — self-contained setup + execution for the LiteLLM supply-chain demo.
#
# Installs ALL prerequisites automatically (Go, clang, libbpf-dev, python3-venv),
# builds leashd, installs litellm 1.82.8, then runs the demo under enforcement.
#
# Requirements on the test VM:
#   • Linux kernel 5.8+  with CONFIG_DEBUG_INFO_BTF=y and cgroup v2
#   • apt-get (Debian / Ubuntu)
#   • sudo / root

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LEASHD_BIN="$REPO_ROOT/bin/leashd"
VENV_DIR="$SCRIPT_DIR/.venv"

GO_VERSION="1.23.8"
GO_TARBALL="go${GO_VERSION}.linux-amd64.tar.gz"
GO_URL="https://go.dev/dl/${GO_TARBALL}"
GO_INSTALL_DIR="/usr/local"

RED="\033[31m"; YELLOW="\033[33m"; GREEN="\033[32m"; CYAN="\033[36m"; RESET="\033[0m"

info()  { echo -e "${CYAN}[setup]${RESET} $*"; }
ok()    { echo -e "${GREEN}[ok]${RESET}    $*"; }
warn()  { echo -e "${YELLOW}[warn]${RESET}  $*"; }
fatal() { echo -e "${RED}[error]${RESET} $*" >&2; exit 1; }

# Must be root for leashd AND for apt / Go install
if [[ $EUID -ne 0 ]]; then
    warn "Not running as root; re-executing with sudo..."
    exec sudo -E env PATH="$PATH" bash "$0" "$@"
fi

# ── 0. System packages (clang, llvm, libbpf-dev, python3-venv) ───────────────

APT_PACKAGES=(clang llvm libbpf-dev python3 python3-venv curl)
MISSING_APT=()
for pkg in "${APT_PACKAGES[@]}"; do
    dpkg -s "$pkg" &>/dev/null || MISSING_APT+=("$pkg")
done

if [[ ${#MISSING_APT[@]} -gt 0 ]]; then
    info "Installing apt packages: ${MISSING_APT[*]}"
    apt-get update -qq
    apt-get install -y -qq "${MISSING_APT[@]}"
    ok "apt packages installed."
else
    ok "apt packages already present."
fi

# ── 1. Go ────────────────────────────────────────────────────────────────────

need_go_install=false
if ! command -v go &>/dev/null; then
    need_go_install=true
else
    current_go="$(go version | awk '{print $3}' | sed 's/go//')"
    # Simple version check: compare major.minor
    required_major=1; required_minor=21
    cur_major="$(echo "$current_go" | cut -d. -f1)"
    cur_minor="$(echo "$current_go" | cut -d. -f2)"
    if [[ "$cur_major" -lt "$required_major" ]] || \
       { [[ "$cur_major" -eq "$required_major" ]] && [[ "$cur_minor" -lt "$required_minor" ]]; }; then
        warn "Go $current_go is too old (need 1.21+); installing Go $GO_VERSION..."
        need_go_install=true
    else
        ok "Go $current_go already installed."
    fi
fi

if [[ "$need_go_install" == true ]]; then
    info "Downloading Go $GO_VERSION..."
    TMP_DIR="$(mktemp -d)"
    curl -fsSL "$GO_URL" -o "$TMP_DIR/$GO_TARBALL"
    info "Installing Go $GO_VERSION to $GO_INSTALL_DIR ..."
    rm -rf "$GO_INSTALL_DIR/go"
    tar -C "$GO_INSTALL_DIR" -xzf "$TMP_DIR/$GO_TARBALL"
    rm -rf "$TMP_DIR"
    # Make available in this session
    export PATH="$GO_INSTALL_DIR/go/bin:$PATH"
    # Persist for future sessions
    GO_PROFILE=/etc/profile.d/go.sh
    echo "export PATH=\$PATH:$GO_INSTALL_DIR/go/bin" > "$GO_PROFILE"
    ok "Go $(go version | awk '{print $3}') installed."
else
    export PATH="$GO_INSTALL_DIR/go/bin:$PATH"
fi

# ── 2. leashd binary ─────────────────────────────────────────────────────────

if [[ ! -x "$LEASHD_BIN" ]]; then
    info "Building leashd from source (this takes ~1 min)..."
    (cd "$REPO_ROOT" && make build)
    ok "leashd built: $LEASHD_BIN"
else
    ok "leashd binary found: $LEASHD_BIN"
fi

# ── 3. Python venv + compromised litellm ────────────────────────────────────

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

# ── 4. Run demo under leashd ────────────────────────────────────────────────

info "Launching demo app under leashd enforcement..."
echo
echo "  Policy file : $SCRIPT_DIR/rules.yaml"
echo "  Default     : BLOCK (deny-all except explicit allows)"
echo "  Allowed     : pypi.org, api.openai.com, api.anthropic.com, loopback"
echo "  Blocked     : everything else (incl. models.litellm.cloud, checkmarx.zone)"
echo

# Check for root — leashd requires CAP_BPF / CAP_NET_ADMIN
# (already handled at top of script, this is a safety net)

exec "$LEASHD_BIN" run \
    --dir "$SCRIPT_DIR" \
    -- \
    "$VENV_DIR/bin/python3" "$SCRIPT_DIR/app.py" "$@"
