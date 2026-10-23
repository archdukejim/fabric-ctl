import os

from fabriclib.common.run import CommandError, run as sh
from fabriclib.setup.errors import SetupError

APT_ENV = {**os.environ, "DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "a"}


def apt_install(pkgs, hint, config=None):
    """Purpose: install packages from the host's own apt sources (fabric adds none), or, offline, from a bundle's
             local source given as an apt configuration (setup/common/install_from_bundle, 2.1.14.16).
    Inputs:  pkgs — package names; hint — what to check when apt fails (added to the error); config — an apt
             configuration file set as APT_CONFIG (None: the host's own sources). Env APT_ENV for apt.
    Returns: None; the packages installed.
    Fails:   SetupError when apt cannot install them; CommandError from `apt-get update` propagates.
    Feeds:   setup/condition_host, setup/join_host_domain, setup/common/install_from_bundle."""
    env = dict(APT_ENV, APT_CONFIG=config) if config else APT_ENV
    sh(["apt-get", "update"], env=env, timeout=900)
    try:
        sh(["apt-get", "install", "-y", "--no-install-recommends", *pkgs], env=env, timeout=1800)
    except CommandError as e:
        raise SetupError(f"apt could not install {' '.join(pkgs)}: {str(e)[-600:]}\n{hint}") from None
