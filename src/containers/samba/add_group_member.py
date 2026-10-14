import ldb

from levels import placement_refusal, role_sites


def add_group_member(samdb, lp, site, group, uid, privileged=None):
    """Purpose: a person in a group, if they are not already (manual 1.6.3.6: the agent may change the groups of its
             site; the root's agent also the organisation's). A group that gives a role — a role group, or one
             nested in one — takes only a person living at that role's site or above (2.1.9.24, manual 1.6.3.18.8).
    Inputs:  samdb — SamDB (as the site's agent); lp — LoadParm (unused); site — str (unused); group — the group's
             name; uid — the person's user name; privileged — the organisation's fabric groups (roles at the top
             site), or None for none named.
    Returns: {"added": bool}.
    Fails:   ldb.LdbError ERR_NO_SUCH_OBJECT for no such group or person; ERR_INSUFFICIENT_ACCESS_RIGHTS for a group
             the agent may not change; ValueError "<uid> lives at …" (placement_refusal) before anything changes.
    Feeds:   directory_ops (op "add_group_member")."""
    base = str(samdb.domain_dn())
    g = samdb.search(base=base, scope=ldb.SCOPE_SUBTREE,
                     expression=f"(&(objectClass=group)(sAMAccountName={ldb.binary_encode(group)}))", attrs=["member"])
    p = samdb.search(base=base, scope=ldb.SCOPE_SUBTREE,
                     expression=f"(&(objectCategory=person)(sAMAccountName={ldb.binary_encode(uid)}))", attrs=["dn"])
    if not g or not p:
        raise ldb.LdbError(ldb.ERR_NO_SUCH_OBJECT, f"no group {group} or no person {uid}")
    if str(p[0].dn).lower() in (str(m).lower() for m in g[0].get("member", [])):
        return {"added": False}
    why = placement_refusal(samdb, str(p[0].dn), role_sites(samdb, str(g[0].dn), privileged or []))
    if why:
        raise ValueError(why)
    samdb.add_remove_group_members(group, [uid], add_members_operation=True)
    return {"added": True}
