import ldb

import paths
from grant_members import tiers
from group_kind import group_kind
from group_store import write_managers

NO_MANAGERS = ("ad", "computed", "filled", "host-group")


def _manager_dn(samdb, t, name, bundles):
    """Purpose: a manager's DN: a person of OU=people (never AD's top tier or one of fabric's own accounts) or a group
             whose members may be managers (not AD's own, nor a computed group).
    Inputs:  samdb — SamDB; t — tiers(); name — the manager's user name or group name; bundles — as group_kind.
    Returns: str.
    Fails:   ValueError saying why it cannot be a manager.
    Feeds:   set_group_managers."""
    found = samdb.search(base=paths.folder_dn(samdb, "people"), scope=ldb.SCOPE_SUBTREE, attrs=["dn"],
                         expression=f"(&(objectClass=user)(!(objectClass=computer))"
                                    f"(sAMAccountName={ldb.binary_encode(name)}))")
    if found:
        dn = str(found[0].dn)
        if dn.lower() in t["ad_top"] or dn.lower() in t["fabric_accounts"]:
            raise ValueError(f"managers: {name} is in AD's top tier or one of fabric's own accounts")
        return dn
    try:
        g = group_kind(samdb, name, bundles)
    except ValueError:
        raise ValueError(f"managers: no person or group {name} in the domain")
    if g["kind"] in ("ad", "computed"):
        raise ValueError(f"managers: {name} is one of AD's own or the grants' computed groups")
    return g["dn"]


def set_group_managers(samdb, lp, site, name, managers, add, remove, only_from="", bundles=()):
    """Purpose: a group's managers and their controls set (manual 1.6.12.5, level 1 of 2.1.6.67): any person or group
             may be a manager; the controls say whether they may add, remove, or both, and may limit adding to people
             already in another group. AD's `managedBy` names the first. Not for groups whose members nobody changes
             by hand (AD's own, the computed ones, those fabric fills, the machine groups, `dc-hosts`).
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused); name — the group;
             managers — list of user or group names (empty: no managers); add, remove — bool; only_from — a group's
             name or ""; bundles — as group_kind.
    Returns: {"name", "managers", "add", "remove", "only_from", "changed"}.
    Fails:   ValueError for a group that takes no managers, a manager that cannot be one, an unknown "only from"
             group, a name given twice; ldb.LdbError.
    Feeds:   directory_ops (op "set_group_managers")."""
    g = group_kind(samdb, name, bundles)
    if g["kind"] in NO_MANAGERS or g["name"].lower() == "dc-hosts":
        raise ValueError(f"{g['name']} takes no managers: its members are not changed by hand")
    if not isinstance(managers, list) or not all(isinstance(m, str) and m.strip() for m in managers):
        raise ValueError("managers: a list of names")
    managers = [m.strip() for m in managers]
    if len({m.lower() for m in managers}) != len(managers):
        raise ValueError("managers: a name given twice")
    t = tiers(samdb)
    dns = [_manager_dn(samdb, t, m, bundles) for m in managers]
    only_from = (only_from or "").strip()
    if only_from:
        group_kind(samdb, only_from, bundles)          # it must be a group of the domain
    record = {"managers": managers, "add": bool(add), "remove": bool(remove), "only_from": only_from}
    changed = write_managers(samdb, g["dn"], record, dns[0] if dns else None)
    return {"name": g["name"], **record, "changed": changed}
