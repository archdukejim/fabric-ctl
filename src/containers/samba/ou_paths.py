"""The OUs an admin may make, and how the console and the CLI name an OU (manual 1.6.12.7, 1.6.13.2): by its path
below the domain, top down ("people/staff", "machines/servers/web"). fabric's fixed OUs are shown, never changed; an
admin's own go under OU=people, OU=service-accounts, OU=groups and each machine type's OU (and under their own there).
OUs grant nothing (2.1.6.72)."""
import re

import ldb

import paths

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,62}$")
ADMIN_ROOTS = ("people", "service-accounts", "groups", "machines/servers", "machines/desktops", "machines/network")
# fabric's own OU names: never an admin's, so a path never reads as one of fabric's folders
FABRIC_NAMES = {n.lower() for n in paths.FOLDERS} | {"fabric", "servers", "desktops", "network"}


def ou_dn(samdb, path):
    """Purpose: an OU's DN from its path.
    Inputs:  samdb — SamDB; path — "a/b/c", top down.
    Returns: str "OU=c,OU=b,OU=a,<domain>".
    Fails:   ValueError for an empty path or a part that is not an OU name.
    Feeds:   create_ou, rename_ou, delete_ou, move_machine, list_ous."""
    parts = [p for p in str(path or "").strip("/").split("/")]
    if not parts or not all(NAME_RE.match(p) for p in parts):
        raise ValueError(f"an OU's path: names of letters, digits, space, _ . -, joined by / (not {path!r})")
    return ",".join(f"OU={p}" for p in reversed(parts)) + f",{samdb.domain_dn()}"


def ou_path(samdb, dn):
    """Purpose: an OU's path from its DN.
    Inputs:  samdb — SamDB; dn — str, an OU's DN inside the domain.
    Returns: str, e.g. "people/staff".
    Fails:   ValueError when dn is not inside the domain.
    Feeds:   list_ous, move_machine."""
    rel = paths.relative(samdb, dn)
    return "/".join(reversed([p.split("=", 1)[1] for p in rel.split(",")]))


def fixed_dns(samdb):
    """Purpose: fabric's fixed OUs (1.6.13.2), lower case.
    Inputs:  samdb — SamDB.
    Returns: set of str.
    Fails:   never.
    Feeds:   is_admin_ou, list_ous."""
    out = {paths.folder_dn(samdb, n).lower() for n in paths.FOLDERS}
    out.add(paths.computed_groups_dn(samdb).lower())
    out |= {paths.machine_type_dn(samdb, k).lower() for k in paths.MACHINE_TYPES}
    return out


def is_admin_ou(samdb, dn):
    """Purpose: whether an OU is an admin's own: below one of ADMIN_ROOTS and not one of fabric's fixed OUs.
    Inputs:  samdb — SamDB; dn — str.
    Returns: bool.
    Fails:   never.
    Feeds:   create_ou, rename_ou, delete_ou, list_ous."""
    low = dn.lower()
    if low in fixed_dns(samdb):
        return False
    return any(low.endswith("," + ou_dn(samdb, r).lower()) for r in ADMIN_ROOTS)


def exists(samdb, dn):
    """Purpose: whether an object is there.
    Inputs:  samdb — SamDB; dn — str.
    Returns: bool.
    Fails:   ldb.LdbError other than "no such object".
    Feeds:   create_ou, rename_ou, move_machine."""
    try:
        return bool(samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["dn"]))
    except ldb.LdbError as e:
        if e.args[0] == ldb.ERR_NO_SUCH_OBJECT:
            return False
        raise
