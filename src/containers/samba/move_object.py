import ldb

from find_machine import find_machine
from find_person import find_person
from group_kind import group_kind
from ou_paths import exists, ou_dn, ou_path, place_ok
from own_object import own_object
import paths

KINDS = ("person", "machine", "group")
# where each kind may go (1.8.8.5): within its own folder's tree only, until what reads only those trees (Keycloak's
# users and group mapping, fabric's finders, the Windows baseline's link at OU=machines) is decided (2.3.8.6, the owner)
WITHIN = {"person": "people", "group": "groups", "machine": "machines"}


def move_object(samdb, lp, site, kind, name, path, bundles=()):
    """Purpose: a person, machine or group moved to another OU (manual 1.8.8.5, "Move to…"; decision 2.1.8.37): its
             groups stay, so its grants, sudo rules, site and type follow it (2.1.6.72, 2.1.6.99), and fabric's access
             GPOs are linked at the domain's root (2.1.6.98). fabric's own objects stay put (2.1.6.100, own_object).
             Each kind stays inside its own folder's tree for now (WITHIN, 2.3.8.6): a person OU=people's, a group
             OU=groups', a machine OU=machines' (its type's OUs and an admin's OUs below them included).
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused: the directory is the
             domain's); kind — "person", "machine" or "group"; name — its user, host or group name; path — the target
             OU's path ("branch", "people/staff"); bundles — the role bundles' groups (ldap_groups).
    Returns: {"kind", "name", "path", "changed": bool}.
    Fails:   ValueError: an unknown kind, a target where it may not go, no such OU, one of fabric's own (saying what it
             is); ldb.LdbError ERR_NO_SUCH_OBJECT (no such object), ERR_ENTRY_ALREADY_EXISTS (a namesake there),
             ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (op "move_object")."""
    if kind not in KINDS:
        raise ValueError(f"kind: one of {', '.join(KINDS)}, not {kind!r}")
    target = ou_dn(samdb, path)
    if not place_ok(samdb, target):
        raise ValueError(f"{path} is one of fabric's closed folders (or AD's Domain Controllers): nothing is moved "
                         "into it (manual 1.8.8.5)")
    if kind in WITHIN:
        home = paths.folder_dn(samdb, WITHIN[kind]).lower()
        if target.lower() != home and not target.lower().endswith("," + home):
            raise ValueError(f"a {kind} moves only within OU={WITHIN[kind]} for now (not {path}, manual 1.8.8.5)")
    if not exists(samdb, target):
        raise ValueError(f"no OU {path}")
    if kind == "machine":
        msg = find_machine(samdb, name)
    elif kind == "person":
        msg = find_person(samdb, name)
    else:
        found = group_kind(samdb, name, bundles)
        msg = samdb.search(base=found["dn"], scope=ldb.SCOPE_BASE, attrs=["dn"])[0]
    why = own_object(samdb, msg, bundles)
    if why:
        raise ValueError(f"{name} is {why}: it stays where fabric put it (manual 1.8.8.5)")
    dn = str(msg.dn)
    if dn.split(",", 1)[1].lower() == target.lower():
        return {"kind": kind, "name": name, "path": ou_path(samdb, target), "changed": False}
    samdb.rename(dn, f"{dn.split(',', 1)[0]},{target}")
    return {"kind": kind, "name": name, "path": ou_path(samdb, target), "changed": True}
