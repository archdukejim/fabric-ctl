import os

from fabriclib.common.run import CommandError, run as sh
from fabriclib.setup.errors import SetupError

APT_ENV = {**os.environ, "DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "a"}


def apt_install(pkgs, hint):
    """Purpose: install packages from the host's own apt sources (fabric adds none).
    Inputs:  pkgs — package names; hint — what to check when apt fails (added to the error). Env APT_ENV for apt.
    Returns: None; the packages installed.
    Fails:   SetupError when apt cannot install them; CommandError from `apt-get update` propagates.
    Feeds:   setup/condition_host, setup/join_host_domain."""
    sh(["apt-get", "update"], env=APT_ENV, timeout=900)
    try:
        sh(["apt-get", "install", "-y", "--no-install-recommends", *pkgs], env=APT_ENV, timeout=1800)
    except CommandError as e:
        raise SetupError(f"apt could not install {' '.join(pkgs)}: {str(e)[-600:]}\n{hint}") from None
