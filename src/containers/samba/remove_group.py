from group_kind import group_kind
from group_store import drop_managers
from group_uses import group_uses

WHY = {"ad": "one of AD's own groups: fabric leaves it as AD has it",
       "computed": "computed for the grants: written only by fabric (manual 1.6.13.4)",
       "tier": "one of the tiers' groups (manual 1.6.12.2): managed by fabric",
       "filled": "a machine type's group, filled by fabric (manual 1.6.13.3)",
       "host-group": "a machine group: delete it with the machine groups (fabricctl machines)",
       "fabric": "one of fabric's own groups (manual 1.6.13.3): managed by fabric",
       "bundle": "a group carrying a fabric role bundle (manual 1.6.8.1): managed by fabric's settings"}


def remove_group(samdb, lp, site, name, bundles=()):
    """Purpose: an admin's own group deleted (manual 1.6.12.5, Delete group), its managers' record with it; refused for
             any of fabric's or AD's own groups, and while it is in use, naming where: a grant (who or where), a sudo
             rule, another group's managers. Its members stay as they are.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused); name — the group's name;
             bundles — the groups carrying a fabric role bundle.
    Returns: {"name"}.
    Fails:   ValueError "no group …", "<name> is <why>: not deleted", "<name> is in use: …"; ldb.LdbError
             ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (op "remove_group")."""
    g = group_kind(samdb, name, bundles)
    if g["kind"] != "own":
        raise ValueError(f"{g['name']} is {WHY[g['kind']]}: not deleted")
    uses = group_uses(samdb, g["name"], g["dn"])
    where = ([f"grant {x}" for x in uses["grants"]] + [f"sudo rule {x}" for x in uses["sudo"]]
             + ([f"the managers of {len(uses['managers_of'])} group(s)"] if uses["managers_of"] else []))
    if where:
        raise ValueError(f"{g['name']} is in use: {', '.join(where)} (manual 1.6.12.5): change those first")
    drop_managers(samdb, g["dn"])
    samdb.delete(g["dn"])
    return {"name": g["name"]}
