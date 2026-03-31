#!/usr/bin/env python3
"""
Sample application for testing leashd network enforcement.

This app makes outbound connections to various destinations so you can
observe how leashd handles allow, warn, and block verdicts.

Usage:
    sudo ./bin/leashd run --dir sample-app -- python3 sample-app/app.py
    sudo ./bin/leashd run --dir sample-app -- python3 sample-app/app.py --category all
    sudo ./bin/leashd run --dir sample-app -- python3 sample-app/app.py --category allowed
"""

import argparse
import socket
import sys
import time
import urllib.request
import urllib.error

# ── Target definitions ──────────────────────────────────────────────────────
# Organised by expected verdict (based on the accompanying rules.yaml).

TARGETS = {
    "allowed": [
        {
            "label": "PyPI (HTTPS)",
            "kind": "http",
            "url": "https://pypi.org/simple/",
            "description": "Package index — allowed by 'pypi' rule",
        },
        {
            "label": "Google APIs (wildcard)",
            "kind": "http",
            "url": "https://storage.googleapis.com/",
            "description": "Wildcard *.googleapis.com — allowed by 'google-apis' rule",
        },
        {
            "label": "Loopback TCP",
            "kind": "tcp",
            "host": "127.0.0.1",
            "port": 19999,
            "description": "Loopback CIDR 127.0.0.0/8 — allowed by 'loopback' rule",
        },
    ],
    "warned": [
        {
            "label": "GitHub (HTTPS)",
            "kind": "http",
            "url": "https://github.com/",
            "description": "Not in any rule — falls through to default action (warn)",
        },
        {
            "label": "Cloudflare DNS (TCP)",
            "kind": "tcp",
            "host": "1.1.1.1",
            "port": 53,
            "description": "Public DNS — no matching rule, default warn",
        },
        {
            "label": "Example.com (HTTP)",
            "kind": "http",
            "url": "http://example.com/",
            "description": "No matching rule — default warn",
        }
    ],
    "blocked": [
        {
            "label": "Blocked IP (TCP)",
            "kind": "tcp",
            "host": "203.0.113.42",
            "port": 443,
            "description": "Explicitly blocked by 'block-bad-ip' rule",
        },
        {
            "label": "Blocked subnet (TCP)",
            "kind": "tcp",
            "host": "198.51.100.1",
            "port": 80,
            "description": "Blocked by 'block-test-net' CIDR rule (198.51.100.0/24)",
        },
        {
            "label": "LiteLLM API",
            "kind": "http",
            "url": "https://docs.litellm.ai/",
            "description": "Blocked by 'block-litellm' rule",
        },
    ],
}

# ── Helpers ──────────────────────────────────────────────────────────────────

BOLD = "\033[1m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"
RESET = "\033[0m"

VERDICT_COLOUR = {"allowed": GREEN, "warned": YELLOW, "blocked": RED}


def banner(text: str) -> None:
    width = 60
    print(f"\n{CYAN}{'═' * width}")
    print(f"  {text}")
    print(f"{'═' * width}{RESET}\n")


def section(verdict: str) -> None:
    colour = VERDICT_COLOUR.get(verdict, RESET)
    print(f"\n{colour}{BOLD}── Expected verdict: {verdict.upper()} ──{RESET}\n")


def try_http(target: dict) -> None:
    url = target["url"]
    print(f"  → HTTP GET {url}")
    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "leashd-sample-app/1.0")
        with urllib.request.urlopen(req, timeout=5) as resp:
            print(f"    ✓ {resp.status} {resp.reason}  ({len(resp.read())} bytes)")
    except urllib.error.URLError as exc:
        print(f"    ✗ Connection failed: {exc.reason}")
    except Exception as exc:
        print(f"    ✗ Error: {exc}")


def try_tcp(target: dict) -> None:
    host, port = target["host"], target["port"]
    print(f"  → TCP connect {host}:{port}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        sock.connect((host, port))
        print(f"    ✓ Connected")
    except (OSError, socket.timeout) as exc:
        print(f"    ✗ Connection failed: {exc}")
    finally:
        sock.close()


def try_dns(target: dict) -> None:
    name = target["name"]
    print(f"  → DNS resolve {name}")
    try:
        addrs = socket.getaddrinfo(name, None, socket.AF_INET)
        ips = sorted({a[4][0] for a in addrs})
        print(f"    ✓ Resolved to {', '.join(ips)}")
    except socket.gaierror as exc:
        print(f"    ✗ Resolution failed: {exc}")


DISPATCHERS = {
    "http": try_http,
    "tcp": try_tcp,
    "dns": try_dns,
}

# ── Main ─────────────────────────────────────────────────────────────────────


def run(categories: list[str], delay: float) -> None:
    banner("leashd sample app — network connection tester")

    for cat in categories:
        targets = TARGETS.get(cat, [])
        if not targets:
            continue
        section(cat)
        for t in targets:
            colour = VERDICT_COLOUR.get(cat, RESET)
            print(f"{colour}{BOLD}[{t['label']}]{RESET}  {t['description']}")
            DISPATCHERS[t["kind"]](t)
            print()
            time.sleep(delay)

    banner("done — check .leashd/events.jsonl for recorded verdicts")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sample app for testing leashd enforcement."
    )
    parser.add_argument(
        "--category",
        choices=["all", "allowed", "warned", "blocked"],
        default="all",
        help="Which category of targets to exercise (default: all)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Seconds to wait between connections (default: 0.5)",
    )
    args = parser.parse_args()

    if args.category == "all":
        cats = ["allowed", "warned", "blocked"]
    else:
        cats = [args.category]

    run(cats, args.delay)


if __name__ == "__main__":
    main()
