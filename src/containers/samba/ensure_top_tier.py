"""AD's top tier (manual 1.6.12.2, 2.1.6.68): an account made a member of Enterprise, Schema and Domain
Admins, inside the DC as the system (fabric's agent accounts may not change those groups, and never should)."""
import ldb

from protect_top_tier import protect_top_tier
from directory_scope import find_people

# AD's top tier, by RID: Enterprise Admins, Schema Admins, Domain Admins
TOP_GROUPS = {519: "Enterprise Admins", 518: "Schema Admins", 512: "Domain Admins"}


def ensure_top_tier(samdb, uid):
    """Purpose: a person in Enterprise Admins, Schema Admins and Domain Admins (the Enterprise Admin, 2.1.6.68), then
             the top tier's denies written at once (protect_top_tier: the Directory Administrators' rights never
             reach them). A second call changes nothing.
    Inputs:  samdb — SamDB (as the system); uid — the person's user name.
    Returns: list of str, what changed.
    Fails:   ValueError "no person <uid> in the domain"; ldb.LdbError from a change.
    Feeds:   ensure_enterprise_admin (setup's fabric-admin)."""
    found = find_people(samdb, f"(sAMAccountName={ldb.binary_encode(uid)})", ["memberOf"])
    if not found:
        raise ValueError(f"no person {uid} in the domain")
    have = {str(g).lower() for g in found[0].get("memberOf", [])}
    sid, done = str(samdb.get_domain_sid()), []
    for rid, name in TOP_GROUPS.items():
        group = samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE, attrs=["sAMAccountName"],
                             expression=f"(objectSid={sid}-{rid})")[0]
        if str(group.dn).lower() in have:
            continue
        samdb.add_remove_group_members(str(group["sAMAccountName"][0]), [uid], add_members_operation=True)
        done.append(f"{uid}: a member of {name}")
    return done + protect_top_tier(samdb)

