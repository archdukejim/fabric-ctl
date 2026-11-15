import os

from fabriclib.common.run import CommandError, run as sh
from fabriclib.setup.errors import SetupError

APT_ENV = {**os.environ, "DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "a"}
# how long apt waits for dpkg's lock: a fresh Ubuntu runs unattended-upgrades in its first minutes, which holds it
# (the 0.10.0 rc's clean VM, 2.3.1.57); apt waits, then fails as before
LOCK_WAIT = ["-o", "DPkg::Lock::Timeout=600"]


def apt_install(pkgs, hint):
    """Purpose: install packages from the host's own apt sources (fabric adds none), waiting up to 10 minutes for
             dpkg's lock while another apt (unattended-upgrades on a fresh host) holds it.
    Inputs:  pkgs — package names; hint — what to check when apt fails (added to the error). Env APT_ENV for apt.
    Returns: None; the packages installed.
    Fails:   SetupError when apt cannot install them (the lock still held after the wait included); CommandError from
             `apt-get update` propagates.
    Feeds:   setup/condition_host, setup/join_host_domain."""
    sh(["apt-get", *LOCK_WAIT, "update"], env=APT_ENV, timeout=900)
    try:
        sh(["apt-get", *LOCK_WAIT, "install", "-y", "--no-install-recommends", *pkgs], env=APT_ENV, timeout=1800)
    except CommandError as e:
        raise SetupError(f"apt could not install {' '.join(pkgs)}: {str(e)[-600:]}\n{hint}") from None
