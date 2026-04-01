# LiteLLM Supply-Chain Attack Demo

Demonstrates how **leashd** blocks the credential-exfiltration behaviour of the
compromised `litellm` 1.82.7 / 1.82.8 packages (TeamPCP campaign, March 2026).

## Background

On 24 March 2026 two malicious versions of `litellm` were pushed to PyPI using
stolen CI credentials.  The payload:

- **1.82.7** — injected credential-stealing code into `proxy/proxy_server.py`
- **1.82.8** — dropped a `.pth` file (`litellm_init.pth`) that ran the payload
  automatically on *every* Python interpreter start, even if `litellm` was never
  imported

Stolen data (SSH keys, cloud tokens, env vars, k8s secrets) was archived,
encrypted, and POSTed to:

| Attacker domain | Role |
|---|---|
| `models.litellm.cloud` | Primary C2 / exfiltration endpoint |
| `checkmarx.zone` | Secondary / backup drop server |

## How leashd stops it

`rules.yaml` uses **`defaults: action: block`** — every outbound connection is
denied unless it matches an explicit `allow` rule.  The only allowed
destinations are:

| Rule | Domain / CIDR | Purpose |
|---|---|---|
| `loopback` | `127.0.0.0/8` | Local traffic |
| `pypi` | `pypi.org`, `files.pythonhosted.org` | `pip install` |
| `openai` | `api.openai.com` | Legitimate LLM calls |
| `anthropic` | `api.anthropic.com` | Legitimate LLM calls |

`models.litellm.cloud` and `checkmarx.zone` match no rule → **blocked at the
kernel level** by the eBPF cgroup/skb filter before a single byte leaves the host.

## Quick start

```bash
# On the test VM (requires root, Linux 5.8+, cgroup v2):
bash samples/litellm-supply-chain/run.sh
```

`run.sh` is fully self-contained:

1. Builds `leashd` from source if the binary is missing
2. Creates a Python venv and installs `litellm==1.82.8`
3. Re-executes itself with `sudo` if not already root
4. Launches `app.py` under `leashd` enforcement

## Manual run

```bash
# Build leashd (once)
make build

# Install Python deps into a venv
python3 -m venv samples/litellm-supply-chain/.venv
samples/litellm-supply-chain/.venv/bin/pip install \
    -r samples/litellm-supply-chain/requirements.txt

# Run under leashd
sudo ./bin/leashd run --dir samples/litellm-supply-chain \
    -- samples/litellm-supply-chain/.venv/bin/python3 \
       samples/litellm-supply-chain/app.py
```

## App phases

| Phase | Flag | What it does |
|---|---|---|
| Exfiltration simulation | `--phase exfil` | POSTs fake stolen data to C2 domains |
| Legitimate LLM calls | `--phase legit` | GETs `api.openai.com`, `api.anthropic.com` |
| Default-block demo | `--phase default-block` | Hits github.com, 1.1.1.1, etc. |
| All (default) | `--phase all` | Runs all three phases |

```bash
# Run without leashd to see raw connection attempts (unsafe on real hosts)
python3 samples/litellm-supply-chain/app.py --no-leashd
```

## Reviewing results

```bash
# Pretty-print all events
cat samples/litellm-supply-chain/.leashd/events.jsonl | python3 -m json.tool

# Show only blocked events
grep '"verdict":"block"' samples/litellm-supply-chain/.leashd/events.jsonl \
    | python3 -m json.tool
```

## Indicators of Compromise (IOCs)

If you're auditing a real system that may have had 1.82.7/1.82.8 installed:

```bash
pip show litellm | grep Version          # look for 1.82.7 or 1.82.8
find / -name litellm_init.pth 2>/dev/null  # .pth persistence file
find ~/.config/sysmon -name sysmon.py 2>/dev/null   # backdoor script
systemctl --user status sysmon 2>/dev/null           # persistence service
```

Rotate **all** secrets on any host that had these versions installed.
