import ldb

from grant_members import group_members

DOMAIN_ADMINS_RID = 512


def domain_admin(samdb, caller):
    """Purpose: whether a person is one of the domain's Domain Admins (manual 1.3.7.12): the members of the group whose
             SID ends in -512, nested groups followed, so a renamed group still counts and a person in a group inside
             it does too.
    Inputs:  samdb — SamDB; caller — the person's user name (sAMAccountName).
    Returns: {"member": bool}.
    Fails:   ldb.LdbError from a search.
    Feeds:   grants_tool (op domain_admin)."""
    base, sid = str(samdb.domain_dn()), str(samdb.get_domain_sid())
    found = samdb.search(base=base, scope=ldb.SCOPE_SUBTREE, expression=f"(objectSid={sid}-{DOMAIN_ADMINS_RID})",
                         attrs=["sAMAccountName"])
    if not found or not caller:
        return {"member": False}
    people = group_members(samdb, str(found[0]["sAMAccountName"][0]))["people"]
    return {"member": any(str(name).lower() == caller.lower() for name in people.values())}
