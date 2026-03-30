# Leashd

**Per-project eBPF network firewall for Linux.**

Leashd enforces domain and IP allowlists at the kernel level. It wraps any command in an isolated cgroup, attaches eBPF programs (kprobes + cgroup/skb filters), and detects or blocks unexpected outbound connections — all without modifying the target application.

```bash
# Scaffold a rules file (auto-detects your package manager)
leashd init

# Run your app under network enforcement
sudo leashd run -- npm install
```

Any connection not matching a rule in `rules.yaml` is logged, warned, or blocked depending on your policy.

---

## Table of Contents

- [Why Leashd?](#why-leashd)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [CLI Reference](#cli-reference)
- [Testing](#testing)
- [CI Pipeline](#ci-pipeline)
- [Debugging](#debugging)
- [Key Gotchas](#key-gotchas)
- [License](#license)

---

## Why Leashd?

Package managers, build tools, and dev scripts make outbound network calls constantly — to registries, CDNs, telemetry endpoints, and sometimes places you don't expect. Supply chain attacks exploit this trust.

Leashd gives you a per-project firewall that:

- **Detects** unexpected outbound connections in real time
- **Warns or blocks** connections not in your allowlist
- **Operates at the kernel level** — no proxy, no iptables rules, no app changes
- **Scopes enforcement to one process tree** via cgroups, so it doesn't affect the rest of your system
- **Hot-reloads** rules without restarting the wrapped process

---

## How It Works

```
                      ┌──────────────────────────────────────────┐
                      │              Linux Kernel                 │
                      │                                          │
  child process ──►   │  cgroup/skb egress filter (per-cgroup)   │ ──► network
  (npm install)       │      ▲           ▲                       │
                      │      │           │                       │
                      │  kprobe:       kprobe:                   │
                      │  tcp_v4_connect  ip4_datagram_connect    │
                      │      │           │                       │
                      │      └─── ring buffer ───┘               │
                      └──────────────┬───────────────────────────┘
                                     │ events
                                     ▼
                      ┌──────────────────────────────────────────┐
                      │           Leashd Daemon (userspace)      │
                      │                                          │
                      │  policy engine → verdict → alert output  │
                      │  rules watcher → hot-reload              │
                      │  DNS refresher → IP cache updates        │
                      └──────────────────────────────────────────┘
```

1. `leashd run` creates an isolated **cgroup v2** and places the child process inside it.
2. **eBPF kprobes** on `tcp_v4_connect` and `ip4_datagram_connect` emit events to a ring buffer whenever the child (or any of its descendants) makes an outbound connection.
3. A **cgroup/skb egress filter** enforces block verdicts at the packet level.
4. The userspace daemon drains events, resolves verdicts against your `rules.yaml`, and routes alerts to the terminal, JSON logs, or webhooks.

---

## Architecture

### Component Overview

```
CLI (cobra) → run command
    ├─ cgroup/manager  — creates isolated cgroup v2, places child PID inside
    ├─ bpf/loader      — loads eBPF objects, attaches kprobes + cgroup/skb filter
    ├─ daemon/daemon    — 5-goroutine event loop
    └─ ipc/server      — Unix socket for `leashd status` queries
```

### Daemon Goroutines

The daemon (`internal/daemon/daemon.go`) runs five concurrent goroutines communicating via buffered channels:

| Goroutine | Responsibility |
|-----------|---------------|
| **runRulesWatcher** | fsnotify watch on `rules.yaml`; triggers hot-reload |
| **runDNSRefresher** | Polls DNS for IP changes; triggers policy recompile |
| **runEventConsumer** | Drains eBPF ring buffer → `eventCh` (4096-buffered) |
| **runPolicyEngine** | Reads `eventCh`, resolves verdict, writes to `enrichCh` (1024-buffered) |
| **runAlertDispatcher** | Reads `enrichCh`, routes to terminal/JSON/webhook outputs |

### eBPF Layer

Source: `ebpf/leashd.c` → compiled via `bpf2go` into `internal/bpf/`

**Programs:**
- Two kprobes: `tcp_v4_connect` (TCP), `ip4_datagram_connect` (UDP, best-effort)
- One cgroup/skb egress filter: per-cgroup packet-level enforcement

**BPF Maps:**

| Map | Type | Size | Purpose |
|-----|------|------|---------|
| `policy_map` | LPM trie | 65,536 entries | IP/CIDR → verdict lookup |
| `tracked_cgroups` | Hash | — | Set of active cgroup IDs |
| `events` | Ring buffer | 4 MiB | Kernel → userspace event stream |

### Policy Engine

Verdict resolution in `internal/policy/engine.go` follows this order:

1. **LPM trie lookup** — exact IP and CIDR prefix match
2. **Reverse DNS** — lookup on unknown IPs
3. **Wildcard domain matching** — e.g., `*.example.com`
4. **Forward-learning cache** — 5-minute TTL for wildcard hits
5. **Default action** — from `rules.yaml` (fallback: `warn`)

Verdicts: `allow` (0), `warn` (1), `block` (2)

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | **Go 1.22** |
| eBPF compiler | **clang/LLVM** → compiled with `bpf2go` from [cilium/ebpf](https://github.com/cilium/ebpf) |
| CLI framework | [cobra](https://github.com/spf13/cobra) |
| DNS resolution | [miekg/dns](https://github.com/miekg/dns) |
| File watching | [fsnotify](https://github.com/fsnotify/fsnotify) |
| Config format | YAML via [go-yaml](https://github.com/go-yaml/yaml) |
| Linter | [golangci-lint](https://golangci-lint.run/) |
| CI E2E VMs | [cilium/little-vm-helper](https://github.com/cilium/little-vm-helper-action) (QEMU) |

---

## Project Structure

```
.
├── cmd/leashd/          # CLI entrypoint
├── ebpf/
│   ├── leashd.c         # eBPF C source (kprobes, cgroup/skb filter)
│   ├── leashd.h         # eBPF shared header
│   └── headers/         # vmlinux.h (pre-committed)
├── internal/
│   ├── bpf/             # bpf2go generated code + loader
│   ├── cgroup/          # cgroup v2 manager
│   ├── cli/             # Cobra command definitions (init, run, status, audit)
│   ├── config/          # rules.yaml schema, parser, language detector
│   ├── daemon/          # 5-goroutine event loop
│   ├── dns/             # DNS resolver and cache
│   ├── ipc/             # Unix socket server for `leashd status`
│   ├── policy/          # Verdict engine (LPM, rDNS, wildcards)
│   └── version/         # Build-time version info
├── tests/e2e/           # End-to-end tests (build tag: e2e)
│   └── helpers/connector/ # TCP/UDP connector binary for E2E
├── testdata/            # Test fixtures (rules.yaml)
├── scripts/             # run-e2e-vm.sh (LVH VM runner)
├── .devcontainer/       # Codespace / devcontainer config
├── .github/workflows/   # CI pipeline (ci.yml)
└── Makefile             # Build, test, lint targets
```

---

## Getting Started

### Prerequisites

- **Linux** with kernel **5.8+** and `CONFIG_DEBUG_INFO_BTF=y` (cgroup v2, ring buffers, BPF CO-RE)
- **cgroup v2 unified hierarchy** mounted at `/sys/fs/cgroup`
- **Root** or capabilities: `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_SYS_ADMIN`
- **Build toolchain** (for compiling eBPF): `clang`, `llvm`, `libbpf-dev`
- **Go 1.22+**

### Recommended: Use the Devcontainer

The fastest way to get a working dev environment is the included devcontainer (works with GitHub Codespaces or VS Code Remote Containers):

```bash
# Open in VS Code → "Reopen in Container"
# Or launch a Codespace from the GitHub repo page
```

The devcontainer is pre-configured with:
- Go 1.22, clang/LLVM, libbpf-dev, bpftool
- `--privileged` mode with cgroup/BTF/debugfs mounts
- QEMU + lvh for local VM-based E2E testing
- golangci-lint, bpf2go, and all required tools

### Manual Setup

```bash
# Install system dependencies (Debian/Ubuntu)
sudo apt-get install -y clang llvm libbpf-dev make

# Install Go tools
go install github.com/cilium/ebpf/cmd/bpf2go@latest

# Clone and build
git clone https://github.com/abdotalema/leashd.git
cd leashd
make build    # Generates eBPF objects + builds bin/leashd
```

### Quick Start

```bash
# 1. Create a rules.yaml for your project
cd /path/to/your/project
leashd init

# 2. Edit rules.yaml to define your allowlist
vim rules.yaml

# 3. Run your command under enforcement
sudo leashd run -- pip install -r requirements.txt

# 4. Check the session status (from another terminal)
leashd status

# 5. Review and promote warned connections to permanent rules
leashd audit
```

---

## Configuration

Leashd is configured via a `rules.yaml` file in your project root.

### Schema

```yaml
version: "1"

project:
  name: "my-app"
  description: "Optional description"

defaults:
  action: warn          # allow | warn | block — applied when no rule matches
  log: true

rules:
  - id: pypi
    comment: "PyPI package index"
    domains: ["pypi.org", "files.pythonhosted.org"]
    ports: [443, 80]
    action: allow

  - id: internal-services
    cidrs: ["10.0.0.0/8"]
    action: allow

  - id: specific-host
    ips: ["1.2.3.4"]
    ports: [443]
    action: block

  - id: wildcard-example
    domains: ["*.googleapis.com"]
    action: allow

notifications:
  terminal: true
  json_log: ".leashd/events.jsonl"
  webhook: "https://hooks.example.com/leashd"
```

### Rule Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique rule identifier |
| `comment` | string | Human-readable description |
| `domains` | string[] | Domain names (supports `*.example.com` wildcards) |
| `cidrs` | string[] | CIDR ranges (e.g., `10.0.0.0/8`) |
| `ips` | string[] | Exact IP addresses |
| `ports` | int[] | Destination ports |
| `action` | string | `allow`, `warn`, or `block` |

### Language Auto-Detection

`leashd init` detects your project language by looking for:

| File | Language |
|------|----------|
| `requirements.txt` | Python |
| `package.json` | JavaScript/Node.js |
| `go.mod` | Go |
| `Cargo.toml` | Rust |

---

## CLI Reference

### `leashd init`

Scaffold a `rules.yaml` with sensible defaults for your project.

```bash
leashd init                    # Auto-detect language and name
leashd init --name my-app      # Override project name
leashd init --force            # Overwrite existing rules.yaml
leashd init --detect=false     # Skip dependency auto-detection
```

### `leashd run`

Run a command under eBPF network enforcement.

```bash
sudo leashd run -- npm install
sudo leashd run -- make build
sudo leashd run --cgroup-name my-cgroup -- python train.py
sudo leashd run --no-daemon -- curl https://example.com  # Dry-run, no enforcement
```

Signals (`SIGTERM`, `SIGINT`) are forwarded to the child process.

### `leashd status`

Query the running leashd session via IPC.

```bash
leashd status           # Human-readable table
leashd status --json    # JSON output
```

Shows: cgroup path/ID, policy version, event counts, violations, events/sec.

### `leashd audit`

Review warned/blocked events and promote connections to permanent rules.

```bash
leashd audit                              # Interactive review
leashd audit --since 1h                   # Only events from the last hour
leashd audit --log .leashd/events.jsonl   # Custom log path
leashd audit --non-interactive --approve-all  # CI-friendly: approve all warns
```

### Global Flags

| Flag | Default | Env Var | Description |
|------|---------|---------|-------------|
| `--log-level` | `info` | `LEASHD_LOG_LEVEL` | Log verbosity (`debug`, `info`, `warn`, `error`) |
| `--dir` | `.` | — | Project directory (where to find `rules.yaml`) |

---

## Testing

Leashd has three test tiers, each with increasing requirements:

### Unit Tests

No root required. Tests pure logic (config parsing, policy resolution, DNS).

```bash
make test
# Or run a specific test:
go test ./internal/... -v -run TestPolicyResolve
```

### Integration Tests

Requires **root**. Tests cgroup management and system interactions (no eBPF kernel needed).

```bash
make test-int
# Or run a specific test:
sudo -E env PATH="$PATH" go test -tags=integration ./internal/cgroup/... -v -run TestCgroupCreate
```

### E2E Tests

Requires **root** + an **eBPF-capable kernel**. Tests the full pipeline (eBPF load → connection → verdict → output).

```bash
# Run directly on host (if kernel supports eBPF)
make test-e2e

# Run inside an LVH VM (recommended — works anywhere with KVM)
make test-e2e-vm                          # Default kernel: 6.6-20260310.122539
LVH_KERNEL=5.15-20260310.122539 make test-e2e-vm    # Specific kernel version
```

### Run All Tests

```bash
make test-all    # unit → integration → e2e (host)
```

### Build Tags

Tests are gated by build tags:

| Tag | Tests |
|-----|-------|
| *(none)* | Unit tests |
| `integration` | Integration tests |
| `e2e` | End-to-end tests |

---

## CI Pipeline

CI is defined in `.github/workflows/ci.yml` and runs on every push and PR:

| Job | Runner | What it does |
|-----|--------|-------------|
| **Unit Tests** | `ubuntu-latest` | `go test ./internal/...` |
| **Integration Tests** | `ubuntu-latest` | `sudo go test -tags=integration` |
| **Build** | `ubuntu-latest` | `make generate build testbin testbin-e2e` → uploads artifacts |
| **E2E (matrix)** | `ubuntu-latest` + LVH VM | Runs E2E in QEMU VMs (kernels: `6.6`, `6.1`, `5.15`) |
| **Lint** | `ubuntu-latest` | `golangci-lint` |

The E2E matrix uses [cilium/little-vm-helper](https://github.com/cilium/little-vm-helper) to spin up ephemeral QEMU VMs with real kernels. To test against a new kernel version, add it to `matrix.kernel` in `ci.yml`. Use date-stamped tags (e.g. `6.1-20260310.122539`); do not use `-main` tags.

---

## Debugging

### Verbose Logging

```bash
sudo leashd run --log-level debug -- <command>
```

This enables debug-level output from the daemon, including:
- eBPF program load/attach status
- DNS resolution results
- Policy verdict decisions per connection
- Ring buffer event details

### Inspecting eBPF State

```bash
# List loaded BPF programs
sudo bpftool prog list

# Dump the policy map contents
sudo bpftool map dump name policy_map

# Check tracked cgroups
sudo bpftool map dump name tracked_cgroups

# View ring buffer stats
sudo bpftool map show name events
```

### Cgroup Inspection

```bash
# Find the leashd cgroup
ls /sys/fs/cgroup/leashd-*/

# Check which PIDs are in the cgroup
cat /sys/fs/cgroup/leashd-*/cgroup.procs
```

### Event Log

Leashd writes structured events to `.leashd/events.jsonl` (if configured in `rules.yaml`):

```bash
# Tail events in real time
tail -f .leashd/events.jsonl | jq .

# Filter for blocked connections
cat .leashd/events.jsonl | jq 'select(.verdict == "block")'
```

Each event contains: `timestamp`, `pid`, `command`, `dst_ip`, `dst_port`, `reverse_dns`, `matched_rule`, `verdict`.

### Common Issues

| Problem | Cause | Fix |
|---------|-------|-----|
| `permission denied` on `leashd run` | Needs root or BPF capabilities | Use `sudo` or grant `CAP_BPF + CAP_NET_ADMIN + CAP_SYS_ADMIN` |
| `cgroup2 not mounted` | System uses cgroup v1 | Ensure cgroup v2 is at `/sys/fs/cgroup` |
| `failed to load BPF program` | Kernel too old or missing BTF | Requires kernel 5.8+ with `CONFIG_DEBUG_INFO_BTF=y` |
| `make generate` fails | Missing clang/llvm | `sudo apt install clang llvm libbpf-dev` |
| Integration tests fail without root | Build tag tests need `sudo -E` | Use `make test-int` (runs with sudo) |
| E2E tests fail on non-eBPF kernel | Host kernel lacks eBPF support | Use `make test-e2e-vm` to run in a VM |

---

## Key Gotchas

- **x86_64 only** — the Makefile hardcodes `-D__TARGET_ARCH_x86` in BPF compilation flags.
- **UDP kprobe is best-effort** — the loader silently ignores `ip4_datagram_connect` attachment failures.
- **Hot-reload clears the learned cache** — all cached wildcard verdicts reset when `rules.yaml` changes.
- **Event channel overflow drops silently** — `eventCh`/`enrichCh` backpressure is not propagated.
- **`sudo -E` is required for tests** — child processes need inherited `PATH`/`GOPATH`/`HOME`.
- **`make clean` removes generated eBPF** — you must run `make generate` (requires clang) afterward.
- **`vmlinux.h` is pre-committed** — don't regenerate unless targeting a different kernel ABI.

---

## License

[MIT](LICENSE) © Abdo Talema
