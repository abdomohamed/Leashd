# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Does

Leashd is a per-project eBPF-based network firewall that enforces domain/IP allowlists at the kernel level. It wraps a child process in a cgroup and uses eBPF kprobes + cgroup/skb filters to detect and block unexpected outbound connections.

## Build Commands

```bash
make build        # Generate BPF objects + build binary (requires clang, llvm, libbpf-dev)
make generate     # Re-run bpf2go to regenerate internal/bpf/leashd_bpf*.go from ebpf/leashd.c
make vmlinux      # Regenerate ebpf/headers/vmlinux.h from running kernel (rarely needed)
make lint         # Run golangci-lint
make release-local # GoReleaser snapshot build (no publish, artifacts in dist/)
make clean        # Remove binaries and generated eBPF objects
```

`vmlinux.h` is pre-committed; do not regenerate it unless intentionally targeting a different kernel ABI.

## Test Commands

```bash
# Unit tests — no root required
make test
go test ./internal/... -v -run TestFooBar

# Integration tests — requires root, no eBPF kernel needed
make test-int
sudo -E env PATH="$PATH" go test -tags=integration ./internal/cgroup/... -v -run TestFooBar

# E2E tests — requires root + eBPF-capable kernel (devcontainer is --privileged)
make test-e2e
# Run a single E2E test:
sudo -E env PATH="$PATH" LEASHD_BIN="$(pwd)/bin/leashd" \
  CONNECTOR_BIN="$(pwd)/tests/e2e/helpers/connector/connector" \
  go test -tags=e2e ./tests/e2e/... -v -run TestFooBar
```

Build tags (`integration`, `e2e`) gate which tests compile. E2E tests call `make build testbin` internally.

### CI E2E: little-vm-helper (lvh)

In CI, E2E tests run inside ephemeral QEMU VMs using [`cilium/little-vm-helper`](https://github.com/cilium/little-vm-helper) against a matrix of kernel versions (e.g. `6.6-20260310.122539`, `6.1-20260310.122539`, `5.15-20260310.122539`). The flow:

1. `build` job: compiles `bin/leashd`, `connector`, and a static `tests/e2e/e2e.test` binary (`make testbin-e2e`) — uploads them as artifacts.
2. `e2e` job (matrix): downloads artifacts, mounts workspace into VM at `/host`, runs `e2e.test` as root inside the VM.

The test binary's path-walking discovery (`bin/leashd`, `tests/e2e/helpers/connector/connector`) works automatically when the binary is executed from `/host`.

To add a kernel to the matrix, add it to `matrix.kernel` in `.github/workflows/ci.yml`. Use date-stamped tags from `quay.io/lvh-images/kind` (e.g. `6.1-20260310.122539`). Do **not** use `-main` tags — they cause a filename mismatch in the LVH action's image-name derivation step.

### Local E2E with LVH VM

Run E2E tests locally inside an LVH VM (requires KVM — available in the devcontainer):

```bash
make test-e2e-vm              # default kernel: 6.6-20260310.122539
LVH_KERNEL=5.15-20260310.122539 make test-e2e-vm   # specific kernel
```

`make test-e2e-vm` builds all binaries, boots `quay.io/lvh-images/kind:$LVH_KERNEL` via QEMU, SSHes in (empty root password), and runs the pre-compiled `e2e.test` binary from the mounted workspace (`/host`). VM images are cached in `~/.cache/lvh`. First run pulls the image (~1–2 GB). Console log: `/tmp/lvh-<kernel>.log`.

To install the tools in an existing session: `make devsetup`.

## Releases

Releases are automated via [GoReleaser](https://goreleaser.com/) and the `.github/workflows/release.yml` workflow.

```bash
# Create a release (triggers CI to build + publish)
git tag v0.2.0
git push origin v0.2.0
```

- Pushing a `v*` tag triggers the release workflow: installs BPF deps → `make generate` → GoReleaser builds Linux amd64 binary → publishes GitHub Release with auto-generated release notes.
- Release notes are grouped by commit type (feat/fix/docs/test/chore) using conventional commit prefixes.
- `make release-local` runs a snapshot build locally (no publish).
- Config: `.goreleaser.yaml`. Version is injected via `-ldflags` into `internal/version.Version`.
- Update `CHANGELOG.md` when preparing a release.

## Architecture

### Component Overview

```
CLI (cobra) → run command
    └─ cgroup/manager  — creates isolated cgroup v2, places child PID inside
    └─ bpf/loader      — loads eBPF objects, attaches kprobes + cgroup/skb filter
    └─ daemon/daemon   — 5-goroutine event loop (see below)
    └─ ipc/server      — Unix socket for `leashd status` queries
```

### Daemon Goroutines (`internal/daemon/daemon.go`)

The daemon runs five concurrent goroutines communicating via channels:

1. **runRulesWatcher** — fsnotify watch on `rules.yaml`; triggers hot-reload
2. **runDNSRefresher** — polls DNS for IP changes; triggers policy recompile
3. **runEventConsumer** — drains eBPF ring buffer → `eventCh` (4096-buffered)
4. **runPolicyEngine** — reads `eventCh`, resolves verdict, writes to `enrichCh` (1024-buffered)
5. **runAlertDispatcher** — reads `enrichCh`, routes to terminal/JSON/webhook outputs

### eBPF Layer (`internal/bpf/`, `ebpf/leashd.c`)

- **Two kprobes**: `tcp_v4_connect`, `ip4_datagram_connect` (UDP best-effort)
- **One cgroup/skb egress filter**: per-cgroup, enforces verdicts
- **Three BPF maps**:
  - `policy_map` (LPM trie, 65536 entries): IP/CIDR → verdict
  - `tracked_cgroups` (hash): set of active cgroup IDs
  - `events` (ring buffer, 4 MiB): kernel → userspace event stream
- `bpf2go` compiles `ebpf/leashd.c` into `internal/bpf/leashd_bpfel.go` / `leashd_bpfeb.go`
- **Cgroup ID resolution**: kprobes use `bpf_get_current_task()` + CO-RE (`BPF_CORE_READ`) to walk `task_struct→cgroups→dfl_cgrp→kn→id` (works on 5.8+). The cgroup/skb program uses the direct `bpf_get_current_cgroup_id()` helper instead.

### Policy Engine (`internal/policy/engine.go`)

Verdict resolution order:
1. LPM trie lookup on exact IP and CIDR prefixes
2. Reverse DNS lookup on unknown IPs
3. Wildcard domain matching (e.g., `*.example.com`)
4. Forward-learning cache (5-minute TTL) for wildcard hits
5. Default action from `rules.yaml` (fallback: WARN)

Verdicts: `VerdictAllow=0`, `VerdictWarn=1`, `VerdictBlock=2`

### Config Schema (`internal/config/schema.go`)

`rules.yaml` structure:
```yaml
version: 1
project: { name, language }
defaults: { action: allow|warn|block, logging: true }
rules:
  - id: string
    domains: ["*.example.com"]
    cidrs: ["10.0.0.0/8"]
    ips: ["1.2.3.4"]
    ports: [443]
    action: allow|warn|block
notifications: { webhook: url }
```

`internal/config/detector.go` auto-detects language from `requirements.txt`, `package.json`, `go.mod`, `Cargo.toml`.

## Runtime Requirements

- **Root or CAP_BPF + CAP_NET_ADMIN + CAP_SYS_ADMIN**
- **Linux kernel 5.8+** with `CONFIG_DEBUG_INFO_BTF=y` (ring buffers, cgroup v2, BPF CO-RE)
- **cgroup v2 unified hierarchy** at `/sys/fs/cgroup` (checked at startup)
- **Build toolchain**: clang, llvm, libbpf-dev (only for `make generate`)

## Key Gotchas

- **Makefile is x86_64 only**: `-D__TARGET_ARCH_x86` is hardcoded in the BPF compilation step.
- **UDP kprobe is best-effort**: loader silently ignores `ip4_datagram_connect` attachment failure.
- **Hot-reload clears the learned cache**: all cached wildcard verdicts reset on `rules.yaml` change.
- **Event channel overflow drops events silently**: `eventCh`/`enrichCh` backpressure is not propagated.
- **`sudo -E` required for integration/e2e tests**: child processes need inherited PATH/GOPATH/HOME.
- **`make clean` removes generated BPF objects**: `make generate` (requires clang) must be re-run after.
- **Devcontainer requires `--cgroupns=host`**: Docker defaults to a private cgroup namespace which prevents cgroup process placement. The devcontainer.json already includes this flag.