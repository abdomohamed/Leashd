# Changelog

All notable changes to Leashd will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [v0.1.0] — Unreleased

Initial release of Leashd — a per-project eBPF network firewall for Linux.

### Added

- **eBPF enforcement engine**: kprobes on `tcp_v4_connect` and `ip4_datagram_connect` with cgroup/skb egress filter for packet-level blocking.
- **Policy engine** with LPM trie lookup, reverse DNS resolution, wildcard domain matching (`*.example.com`), and forward-learning cache (5-minute TTL).
- **`leashd init`**: scaffold `rules.yaml` with language auto-detection (Python, Node.js, Go, Rust).
- **`leashd run`**: wrap any command in an isolated cgroup v2 with real-time eBPF network enforcement.
- **`leashd status`**: query running sessions via Unix socket IPC (human-readable and JSON output).
- **`leashd audit`**: review warned/blocked events and promote connections to permanent rules.
- **Hot-reload**: fsnotify watch on `rules.yaml` triggers live policy recompilation without restarting the child process.
- **DNS refresher**: periodic polling detects IP changes for domain-based rules.
- **Multiple output targets**: terminal (colored), JSON log (`.leashd/events.jsonl`), and webhook notifications.
- **Signal forwarding**: `SIGTERM`/`SIGINT` are forwarded to the child process for graceful shutdown.
- **CI pipeline**: unit tests, integration tests (cgroup), E2E tests across kernel 5.15/6.1/6.6 via cilium/little-vm-helper QEMU VMs, and golangci-lint.

### Requirements

- Linux kernel 5.8+ with `CONFIG_DEBUG_INFO_BTF=y`
- cgroup v2 unified hierarchy
- Root or `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_SYS_ADMIN`

[v0.1.0]: https://github.com/abdotalema/leashd/releases/tag/v0.1.0
