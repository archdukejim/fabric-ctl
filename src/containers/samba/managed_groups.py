import ldb

from grant_members import group_members
from group_store import all_managers


def managed_groups(samdb, user):
    """Purpose: the groups a person manages (manual 1.8.6.6 "Groups I manage", 2.1.6.67): each group whose managers
             name them, or a group they are in (nesting followed), with its controls and its members by name.
    Inputs:  samdb — SamDB (read only); user — the person's user name.
    Returns: {"groups": [{"name", "add", "remove", "only_from", "members": [names]}]}, by name.
    Fails:   ValueError for a user who is not a person of the domain; ldb.LdbError.
    Feeds:   grants_tool (op "managed")."""
    found = samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE, attrs=["dn"],
                         expression=f"(&(objectClass=user)(!(objectClass=computer))"
                                    f"(sAMAccountName={ldb.binary_encode(user)}))")
    if not found:
        raise ValueError(f"you ({user}) are not a person of the domain")
    dn, out, cache = str(found[0].dn).lower(), [], {}
    for rec in all_managers(samdb):
        def holds(name):
            if name not in cache:
                cache[name] = group_members(samdb, name)["people"]
            return dn in cache[name]
        if not any(m.lower() == user.lower() or holds(m) for m in rec["managers"]):
            continue
        res = samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE, attrs=["sAMAccountName", "member"],
                           expression=f"(objectGUID={rec['guid']})")
        if not res:
            continue
        members = []
        for m in res[0].get("member", []):
            got = samdb.search(base=str(m), scope=ldb.SCOPE_BASE, attrs=["sAMAccountName"])
            if got:
                members.append(str(got[0]["sAMAccountName"][0]))
        out.append({"name": str(res[0]["sAMAccountName"][0]), "add": rec["add"], "remove": rec["remove"],
                    "only_from": rec["only_from"], "members": sorted(members, key=str.lower)})
    return {"groups": sorted(out, key=lambda g: g["name"].lower())}
