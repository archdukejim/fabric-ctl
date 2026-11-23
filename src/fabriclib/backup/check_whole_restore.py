import os

from fabriclib.backup.bundle_key_from import bundle_key_from
from fabriclib.backup.check_bundle import check_bundle
from fabriclib.backup.check_changes import NETWORK
from fabriclib.backup.fabric_version import fabric_version
from fabriclib.common.errors import ValidationError
from fabriclib.setup.common.network_problem import network_problem


def check_whole_restore(base, path, key, package_version, problem=network_problem, opens=bundle_key_from):
    """Purpose: whether a bundle can be restored whole onto this host, unchanged, checked while fabric still runs, so
             the console's whole restore (`fabricctl reinstall --from`, manual 1.3.7.9) refuses before anything is
             stopped: what restore_bundle would refuse after the uninstall.
    Inputs:  base — install root; path — the bundle; key — {"passphrase"} or {"private_key"}; package_version — the
             installed package's version; problem, opens — network_problem and bundle_key_from (tests).
    Returns: the bundle's manifest.
    Fails:   ValidationError: a bundle that is not whole, made by a newer fabric, of another install root, its addresses
             not this host's (network_problem's words), a wrong key.
    Feeds:   run_reinstall_command (--from), agent/post_backup (reinstall)."""
    manifest = check_bundle(path)
    made, have = fabric_version(manifest.get("fabric_version")), fabric_version(package_version)
    if made and have and made > have:
        raise ValidationError(f"the bundle was made by fabric {manifest['fabric_version']}, newer than this "
                              f"install ({package_version}): update fabric first")
    if os.path.normpath(manifest.get("base") or base) != os.path.normpath(base):
        raise ValidationError(f"the bundle is of an install at {manifest['base']}, not {base}")
    addresses = {k: manifest.get(k) for k in NETWORK}
    found = problem(addresses) if all(addresses.values()) else ""
    if found:
        raise ValidationError(f"{found}. This bundle is of another address: restore it by the move procedure "
                              "(manual 4.2.4.8)")
    opens(path, **key)
    return manifest
