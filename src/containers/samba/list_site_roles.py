import ldb

from levels import misplaced
import paths
from site_roles import CONSOLE_ROLES, GRANT_MARK, grant_group, grantable


def _cn(dn):
    """Purpose: the first RDN's value of a DN ("CN=lab-admins,OU=…" -> "lab-admins").
    Inputs:  dn — str.
    Returns: str.
    Fails:   never.
    Feeds:   list_site_roles."""
    return dn.split(",", 1)[0].split("=", 1)[1]


def list_site_roles(samdb, lp, site, privileged=None):
    """Purpose: the roles granted at this site and at every site below it (2.1.9.21, manual 1.9.8.20): for each
             grantable role its group and who is in it; never a sibling's or a parent's (2.1.9.22).
    Inputs:  samdb — SamDB (as the site's agent); lp — LoadParm (unused); site — str, this install's site; privileged —
             the organisation's fabric groups (roles at the top site), or None.
    Returns: {"sites": [{"site", "own" (bool: this site, whose roles only a site above grants), "roles": [{"role",
             "kind" ("ad" or "console"), "bundle" (the console's bundle, "" for an AD role), "group", "exists",
             "members" [names], "admins" (bool: the site's own admins hold it), "pending" (bool: they hold an AD role
             without a grant: an older default the next convergence takes away)}], "misplaced": [{"uid", "lives",
             "holds": {site: [groups]}}] (people of the site holding a role beyond it, 2.1.9.24: reported, never
             moved)}]}, this site first.
    Fails:   LookupError when this site has no OU; ldb.LdbError from a search.
    Feeds:   directory_ops (op "list_site_roles")."""
    out = []
    for each in [site] + paths.below(samdb, site):
        groups = f"OU=groups,{paths.site_dn(samdb, each)}"
        admins = f"CN={each}-admins,{groups}".lower()
        roles = []
        for role in grantable():
            name = grant_group(each, role)
            res = samdb.search(base=groups, scope=ldb.SCOPE_ONELEVEL, attrs=["member", "adminDescription"],
                               expression=f"(&(objectClass=group)(sAMAccountName={ldb.binary_encode(name)}))")
            members = [str(m) for m in res[0].get("member", [])] if res else []
            held = admins in [m.lower() for m in members]
            marked = bool(res) and str(res[0].get("adminDescription", [""])[0]) == GRANT_MARK
            console = role in CONSOLE_ROLES
            roles.append({"role": role, "kind": "console" if console else "ad",
                          "bundle": CONSOLE_ROLES[role][0] if console else "", "group": name, "exists": bool(res),
                          "members": sorted(_cn(m) for m in members), "admins": held,
                          "pending": held and not console and not marked})
        lost = [{k: m[k] for k in ("uid", "lives", "holds")} for m in misplaced(samdb, each, privileged or [])]
        out.append({"site": each, "own": each == site, "roles": roles, "misplaced": lost})
    return {"sites": out}
