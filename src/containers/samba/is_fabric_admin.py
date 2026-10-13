import ldb

from site_roles import FABRIC_ADMINS, fabric_admins

IN_CHAIN = "1.2.840.113556.1.4.1941"        # LDAP_MATCHING_RULE_IN_CHAIN: membership through nested groups too


def is_fabric_admin(samdb, lp, site, uid):
    """Purpose: whether a person is one of the fabric admins (manual 1.6.11.2): a member, directly or through nested
             groups, of the organisation's `fabric-admins` or the site's `<site>-fabric-admins` — who may get an SSH
             certificate (1.6.11.9.3, 2.1.7.12).
    Inputs:  samdb — SamDB (as the site's agent); lp — LoadParm (unused); site — str; uid — the user name.
    Returns: {"uid", "fabric_admin": bool, "via": [the groups found, of the two]}.
    Fails:   ValueError("no such user: …") for a name that is not a person (kind "invalid"); ldb.LdbError from a search.
    Feeds:   directory_ops (op "is_fabric_admin") <- fabriclib/directory/is_fabric_admin."""
    base = samdb.domain_dn()
    person = samdb.search(base=base, scope=ldb.SCOPE_SUBTREE, attrs=["dn"],
                          expression=f"(&(objectCategory=person)(objectClass=user)"
                                     f"(sAMAccountName={ldb.binary_encode(uid)}))")
    if len(person) != 1:
        raise ValueError(f"no such user: {uid}")
    via = []
    for name in (FABRIC_ADMINS, fabric_admins(site)):
        group = samdb.search(base=base, scope=ldb.SCOPE_SUBTREE, attrs=["dn"],
                             expression=f"(&(objectClass=group)(sAMAccountName={ldb.binary_encode(name)}))")
        if len(group) != 1:
            continue
        found = samdb.search(base=str(person[0].dn), scope=ldb.SCOPE_BASE, attrs=["dn"],
                             expression=f"(memberOf:{IN_CHAIN}:={ldb.binary_encode(str(group[0].dn))})")
        if found:
            via.append(name)
    return {"uid": uid, "fabric_admin": bool(via), "via": via}
