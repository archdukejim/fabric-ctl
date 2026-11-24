import os

from fabriclib.backup.require_all_sections import require_all_sections
from fabriclib.backup.bundle_key_from import bundle_key_from
from fabriclib.backup.check_bundle import check_bundle
from fabriclib.backup.check_changes import NETWORK, check_changes
from fabriclib.backup.fabric_version import fabric_version
from fabriclib.common.errors import ValidationError
from fabriclib.setup.common.network_problem import network_problem


def check_whole_restore(base, path, key, package_version, changes=None, problem=network_problem,
                        opens=bundle_key_from):
    """Purpose: whether a bundle can be restored whole onto this host, checked before anything is unpacked or
             stopped: the console's whole restore (`fabricctl reinstall --from`, manual 1.3.7.9) while fabric still
             runs, the setup site's restore (1.3.7.10) with the changes asked; what restore_bundle would refuse later.
    Inputs:  base — install root; path — the bundle; key — {"passphrase"} or {"private_key"}; package_version — the
             installed package's version; changes — {key: value} of 1.3.7.7 (none: the bundle's own addresses);
             problem, opens — network_problem and bundle_key_from (tests).
    Returns: the bundle's manifest.
    Fails:   ValidationError: a bundle that is not whole, made by a newer fabric, of another install root, a change
             check_changes refuses, the addresses (the bundle's, or the changed ones) not this host's
             (network_problem's words), a wrong key.
    Feeds:   run_reinstall_command (--from), agent/post_backup (reinstall), setup/site/ask_restore."""
    manifest = check_bundle(path)
    require_all_sections(manifest)
    made, have = fabric_version(manifest.get("fabric_version")), fabric_version(package_version)
    if made and have and made > have:
        raise ValidationError(f"the bundle was made by fabric {manifest['fabric_version']}, newer than this "
                              f"install ({package_version}): update fabric first")
    if os.path.normpath(manifest.get("base") or base) != os.path.normpath(base):
        raise ValidationError(f"the bundle is of an install at {manifest['base']}, not {base}")
    if changes:
        check_changes(changes, manifest)
    addresses = {k: (changes or {}).get(k, manifest.get(k)) for k in NETWORK}
    found = problem(addresses) if all(addresses.values()) else ""
    if found and changes and set(changes) & set(NETWORK):
        raise ValidationError(f"{found}. Give this host its new address first, then restore (manual 4.2.4.8)")
    if found:
        raise ValidationError(f"{found}. This bundle is of another address: restore it by the move procedure "
                              "(manual 4.2.4.8)")
    opens(path, **key)
    return manifest
