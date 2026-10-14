import ldb

from levels import role_sites, site_of
import paths


def move_person(samdb, lp, site, uid, target, privileged=None):
    """Purpose: move a person's account to another site's OU=people (2.1.9.24, manual 1.6.3.18.8, 4.6.1.5): how an
             account comes to live at the level of the roles it holds. Only from a site above both: the person's
             current site and the target must each be this site or below it (a branch cannot move anyone to above
             itself). Never to a site below one where the person holds a role. The account keeps its name, password,
             groups and POSIX ids; it also joins `<target>-users` (signing in at the target's pages).
    Inputs:  samdb — SamDB (as this site's agent: AD's limits on it apply too); lp — LoadParm (unused); site — str,
             this install's site; uid — the person's user name; target — str, the site to move them to; privileged —
             the organisation's fabric groups (roles at the top site), or None.
    Returns: {"uid", "from" (site), "to" (site), "moved" (bool: False when they already live there)}.
    Fails:   ValueError "no person <uid>…", "only a site above both may move …", the placement refusal (a role the
             new place cannot hold); LookupError for an unknown target; ldb.LdbError (ERR_INSUFFICIENT_ACCESS_RIGHTS).
    Feeds:   directory_ops (op "move_person")."""
    res = samdb.search(base=paths.sites_dn(samdb), scope=ldb.SCOPE_SUBTREE, attrs=["cn"],
                       expression="(&(objectCategory=person)(objectClass=user)"
                                  f"(sAMAccountName={ldb.binary_encode(uid)}))")
    if not res or ",OU=service-accounts," in str(res[0].dn):
        raise ValueError(f"no person {uid} in the sites' OUs")
    dn = str(res[0].dn)
    here = [site] + paths.below(samdb, site)
    lives = site_of(samdb, dn)
    if lives not in here or target not in here:
        raise ValueError(f"only a site above both may move {uid} from {lives} to {target}: {site} is not above "
                         f"{lives if lives not in here else target} (run it at a site above both)")
    if lives == target:
        return {"uid": uid, "from": lives, "to": target, "moved": False}
    new = f"{dn.split(',', 1)[0]},OU=people,{paths.site_dn(samdb, target)}"
    sites = role_sites(samdb, dn, privileged or [])
    bad = sorted(s for s in sites if target not in [s] + paths.ancestors(samdb, s))
    if bad:
        raise ValueError(f"{uid} holds a role at {', '.join(bad)}, which an account living at {target} may not hold "
                         f"(2.1.9.24): move it to {bad[0]} or a site above it")
    samdb.rename(dn, new)
    users = f"{target}-users"
    group = samdb.search(base=f"OU=groups,{paths.site_dn(samdb, target)}", scope=ldb.SCOPE_ONELEVEL,
                         attrs=["member"], expression=f"(sAMAccountName={ldb.binary_encode(users)})")
    if group and new.lower() not in [str(m).lower() for m in group[0].get("member", [])]:
        samdb.add_remove_group_members(users, [uid], add_members_operation=True)
    return {"uid": uid, "from": lives, "to": target, "moved": True}
