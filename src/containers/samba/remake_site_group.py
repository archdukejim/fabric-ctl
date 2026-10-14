import paths
from role_groups import branch_made, find_group, make_group
from site_roles import grant_group, grantable


def remake_site_group(samdb, lp, site, target, role):
    """Purpose: a site above makes one of a site's role groups again (2.1.9.21, manual 4.9.1.2; 2.3.9.2.8 option (a)):
             one the site made itself (owned by its own agent, OU admins or admins: deleted and made again there,
             which convergence refuses) is deleted and made again, empty; a missing one is made; one fabric made is
             left as it is. `admins` names `<target>-admins`, which no grant makes. Only a site above the target may
             do it: never a site itself, a sibling or a site below. The group gets its rights and denies at the next
             convergence of the site or of a site above it.
    Inputs:  samdb — SamDB (as this site's agent: AD's limits on it apply too); lp — LoadParm (unused); site — str,
             this install's site; target — str, the site whose group it is; role — "admins" or one of
             site_roles.grantable().
    Returns: {"site": target, "role", "group", "remade" (bool: a group the site had made was replaced), "made"
             (bool: the group was missing and is made), "changed" (bool)}.
    Fails:   ValueError "<role> is not a group a site above can make again (…)", "only a site above <target> may make
             its groups again…"; LookupError for an unknown site; ldb.LdbError (ERR_INSUFFICIENT_ACCESS_RIGHTS);
             ValueError from alloc_id (the block's range full).
    Feeds:   directory_ops (op "remake_site_group")."""
    roles = ["admins"] + grantable()
    if role not in roles:
        raise ValueError(f"{role} is not a group a site above can make again ({', '.join(roles)})")
    if target not in paths.below(samdb, site):
        raise ValueError(f"only a site above {target} may make its groups again: {site} is not above it"
                         + (" (a site cannot repair its own)" if target == site else ""))
    name = f"{target}-admins" if role == "admins" else grant_group(target, role)
    groups = f"OU=groups,{paths.site_dn(samdb, target)}"
    res = find_group(samdb, groups, name)
    remade = bool(res) and branch_made(samdb, target, str(res[0].dn))
    if remade:
        samdb.delete(str(res[0].dn))
    if remade or not res:
        make_group(samdb, target, role, name, groups)
    return {"site": target, "role": role, "group": name, "remade": remade, "made": not res,
            "changed": remade or not res}
