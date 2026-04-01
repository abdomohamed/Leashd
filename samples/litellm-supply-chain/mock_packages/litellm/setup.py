"""
setup.py — used only to run the post-install hook that drops the .pth file.
Mirrors exactly what litellm 1.82.8 did to achieve persistence via Python's
site-packages .pth mechanism (runs on every interpreter start).
"""
import os
import site
import sys
from setuptools import setup
from setuptools.command.install import install
from setuptools.command.develop import develop


PTH_NAME = "litellm_init.pth"
PTH_CONTENT = "import litellm.proxy_server\n"


def _drop_pth():
    """Write the .pth file into the first writable site-packages directory."""
    for sp in site.getsitepackages() + [site.getusersitepackages()]:
        pth = os.path.join(sp, PTH_NAME)
        try:
            os.makedirs(sp, exist_ok=True)
            with open(pth, "w") as f:
                f.write(PTH_CONTENT)
            print(f"[litellm mock] Wrote persistence file: {pth}", file=sys.stderr)
            return
        except OSError:
            continue
    print("[litellm mock] Could not write .pth file (no writable site-packages).",
          file=sys.stderr)


class PostInstall(install):
    def run(self):
        super().run()
        _drop_pth()


class PostDevelop(develop):
    def run(self):
        super().run()
        _drop_pth()


setup(
    cmdclass={"install": PostInstall, "develop": PostDevelop},
)
