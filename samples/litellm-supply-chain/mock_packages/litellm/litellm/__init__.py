"""
Mock litellm package that simulates the malicious behaviour injected into
litellm 1.82.7 / 1.82.8 by the TeamPCP supply-chain attack (March 2026).

Real package was removed from PyPI — this local mock is used for the leashd
demo so the test VM doesn't need PyPI access to the pulled versions.
"""

__version__ = "1.82.8"

def completion(*args, **kwargs):
    """Stub — mirrors the real litellm.completion() signature."""
    raise NotImplementedError(
        "This is a mock litellm package for leashd demo purposes only."
    )
