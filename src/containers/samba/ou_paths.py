"""The OUs an admin may make, and how the console and the CLI name an OU (manual 1.6.12.7, 1.6.13.2): by its path
below the domain, top down ("people/staff", "machines/servers/web"). fabric's fixed OUs are shown, never changed; since
0.9.1 an admin's own go anywhere (1.8.8.5, 2.1.6.101): at the domain's root, under OU=people, OU=service-accounts,
OU=groups, OU=machines and each machine type's OU, or under another of their own; never inside fabric's closed folders
(the fabric hosts, devices, device roles, networks, sudo rules, the grants' computed groups) nor AD's Domain
Controllers. OUs grant nothing (2.1.6.72)."""
import re

import ldb

import paths

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,62}$")
ADMIN_ROOTS = ("people", "service-accounts", "groups", "machines", "machines/servers", "machines/desktops",
               "machines/network")
# fabric's folders that hold only what fabric puts there: no admin's OU and no moved object goes in them (1.8.8.5)
CLOSED = ("fabric-hosts", "devices", "device-roles", "networks", "sudoers")
# fabric's own OU names: never an admin's, so a path never reads as one of fabric's folders
FABRIC_NAMES = {n.lower() for n in paths.FOLDERS} | {"fabric", "servers", "desktops", "network"}


def ou_dn(samdb, path):
    """Purpose: an OU's DN from its path.
    Inputs:  samdb — SamDB; path — "a/b/c", top down.
    Returns: str "OU=c,OU=b,OU=a,<domain>".
    Fails:   ValueError for an empty path or a part that is not an OU name.
    Feeds:   create_ou, rename_ou, delete_ou, move_object, list_ous."""
    parts = [p for p in str(path or "").strip("/").split("/")]
    if not parts or not all(NAME_RE.match(p) for p in parts):
        raise ValueError(f"an OU's path: names of letters, digits, space, _ . -, joined by / (not {path!r})")
    return ",".join(f"OU={p}" for p in reversed(parts)) + f",{samdb.domain_dn()}"


def ou_path(samdb, dn):
    """Purpose: an OU's path from its DN.
    Inputs:  samdb — SamDB; dn — str, an OU's DN inside the domain.
    Returns: str, e.g. "people/staff".
    Fails:   ValueError when dn is not inside the domain.
    Feeds:   list_ous, move_object."""
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


def closed_dns(samdb):
    """Purpose: the OUs no admin's folder and no moved object goes into (1.8.8.5): fabric's closed folders, the grants'
             computed groups' OU and AD's Domain Controllers, lower case.
    Inputs:  samdb — SamDB.
    Returns: set of str.
    Fails:   never.
    Feeds:   is_admin_ou."""
    out = {paths.folder_dn(samdb, n).lower() for n in CLOSED}
    out.add(paths.computed_groups_dn(samdb).lower())
    out.add(f"ou=domain controllers,{samdb.domain_dn()}".lower())
    return out


def is_admin_ou(samdb, dn):
    """Purpose: whether an OU is an admin's own (since 0.9.1 anywhere, 2.1.6.101): not one of fabric's fixed OUs, not
             AD's Domain Controllers, and not inside one of fabric's closed folders.
    Inputs:  samdb — SamDB; dn — str, an OU inside the domain.
    Returns: bool.
    Fails:   never.
    Feeds:   create_ou, rename_ou, delete_ou, list_ous, place_ok, ensure_ou_rights."""
    low = dn.lower()
    if low in fixed_dns(samdb) or not low.endswith("," + str(samdb.domain_dn()).lower()):
        return False
    return not any(low == c or low.endswith("," + c) for c in closed_dns(samdb))


def place_ok(samdb, dn):
    """Purpose: whether a new OU, a new object (Create in..., 2.1.6.101) or a moved one (1.8.8.5) may go into an OU: the
             domain's root (for an OU), one of ADMIN_ROOTS, or an admin's own OU anywhere.
    Inputs:  samdb — SamDB; dn — str, the target's DN (the domain's own DN for its root).
    Returns: bool.
    Fails:   never.
    Feeds:   create_ou, move_object, create_person, create_group, create_machine."""
    low = dn.lower()
    if low == str(samdb.domain_dn()).lower() or low in {ou_dn(samdb, r).lower() for r in ADMIN_ROOTS}:
        return True
    return is_admin_ou(samdb, dn)


def exists(samdb, dn):
    """Purpose: whether an object is there.
    Inputs:  samdb — SamDB; dn — str.
    Returns: bool.
    Fails:   ldb.LdbError other than "no such object".
    Feeds:   create_ou, rename_ou, move_object."""
    try:
        return bool(samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["dn"]))
    except ldb.LdbError as e:
        if e.args[0] == ldb.ERR_NO_SUCH_OBJECT:
            return False
        raise
