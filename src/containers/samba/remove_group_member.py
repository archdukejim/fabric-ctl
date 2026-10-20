import ldb


def remove_group_member(samdb, lp, site, group, uid):
    """Purpose: a person out of a group, if they are in it (manual 1.6.3.16; the agent may change the groups in
             OU=groups: 1.6.13.2).
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused); group — the group's
             name; uid — the person's user name.
    Returns: {"removed": bool}.
    Fails:   ldb.LdbError ERR_NO_SUCH_OBJECT for no such group or person; ERR_INSUFFICIENT_ACCESS_RIGHTS for a group
             the agent may not change.
    Feeds:   directory_ops (op "remove_group_member")."""
    base = str(samdb.domain_dn())
    g = samdb.search(base=base, scope=ldb.SCOPE_SUBTREE,
                     expression=f"(&(objectClass=group)(sAMAccountName={ldb.binary_encode(group)}))", attrs=["member"])
    p = samdb.search(base=base, scope=ldb.SCOPE_SUBTREE,
                     expression=f"(&(objectCategory=person)(sAMAccountName={ldb.binary_encode(uid)}))", attrs=["dn"])
    if not g or not p:
        raise ldb.LdbError(ldb.ERR_NO_SUCH_OBJECT, f"no group {group} or no person {uid}")
    if str(p[0].dn).lower() not in (str(m).lower() for m in g[0].get("member", [])):
        return {"removed": False}
    samdb.add_remove_group_members(group, [uid], add_members_operation=False)
    return {"removed": True}
