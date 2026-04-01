# Leashd Sample App

A Python app that makes outbound connections to various destinations, demonstrating leashd's **allow**, **warn**, and **block** verdicts.

## Quick Start

```bash
# 1. Build leashd (if not already built)
make build

# 2. Run the sample app under leashd enforcement
sudo ./bin/leashd run --dir sample-app -- python3 sample-app/app.py
```

## Targets

| Category  | Target              | Why                                         |
|-----------|---------------------|---------------------------------------------|
| **Allow** | pypi.org            | Matched by `pypi` rule                      |
| **Allow** | *.googleapis.com    | Matched by `google-apis` wildcard rule      |
| **Allow** | 127.0.0.1:19999     | Matched by `loopback` CIDR rule             |
| **Warn**  | github.com          | No matching rule → default action (`warn`)  |
| **Warn**  | 1.1.1.1:53          | No matching rule → default action           |
| **Warn**  | example.com         | No matching rule → default action           |
| **Block** | 203.0.113.42:443    | Matched by `block-bad-ip` rule              |
| **Block** | 198.51.100.1:80     | Matched by `block-test-net` CIDR rule       |
| **Block** | docs.litellm.ai     | Matched by `block-litellm` rule             |

## Options

```bash
# Run only specific categories
sudo ./bin/leashd run --dir sample-app -- python3 sample-app/app.py --category allowed
sudo ./bin/leashd run --dir sample-app -- python3 sample-app/app.py --category blocked

# Adjust delay between connections (seconds)
sudo ./bin/leashd run --dir sample-app -- python3 sample-app/app.py --delay 1.0

# Drop child to a specific user (default: auto-detected from SUDO_UID)
sudo ./bin/leashd run --dir sample-app --user vscode -- python3 sample-app/app.py

# Keep child running as root (not recommended)
sudo ./bin/leashd run --dir sample-app --no-drop-privs -- python3 sample-app/app.py
```

## Reviewing Results

```bash
# Pretty-print the event log
cat sample-app/.leashd/events.jsonl | python3 -m json.tool

# Filter for blocked events
grep '"block"' sample-app/.leashd/events.jsonl | python3 -m json.tool
```
