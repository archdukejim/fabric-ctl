import ldb

from levels import IN_CHAIN, placement_refusal
import paths
from role_groups import branch_made, find_group, make_group
from site_roles import GRANT_MARK, grant_group, grantable


def _member_dn(samdb, name):
    """Purpose: who a role may be granted to: a group or a person, by name, under OU=sites (never a service account
             or a machine).
    Inputs:  samdb — SamDB; name — sAMAccountName.
    Returns: str, the DN.
    Fails:   ValueError "no group or person <name>"; ldb.LdbError from the search.
    Feeds:   grant_site_role."""
    res = samdb.search(base=paths.sites_dn(samdb), scope=ldb.SCOPE_SUBTREE, attrs=["dn"],
                       expression=f"(&(|(objectClass=group)(&(objectCategory=person)(objectClass=user)))"
                                  f"(!(objectClass=computer))(sAMAccountName={ldb.binary_encode(name)}))")
    if not res or ",OU=service-accounts," in str(res[0].dn):
        raise ValueError(f"no group or person {name} in the sites' OUs")
    return str(res[0].dn)


def _is_person(samdb, dn):
    """Purpose: whether a DN is a person's (not a group's).
    Inputs:  samdb — SamDB; dn — str.
    Returns: bool.
    Fails:   ldb.LdbError from the search.
    Feeds:   grant_site_role."""
    return bool(samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["dn"],
                             expression="(&(objectCategory=person)(objectClass=user))"))


def grant_site_role(samdb, lp, site, target, role, member="", grant=True):
    """Purpose: a role at a site below granted to a group or person, or taken back (2.1.9.21, manual 1.9.8.20): the
             member put in, or taken out of, the role's group `<target>-<role>` in the target's OU=groups (a console
             role's group made there first if the target has not converged 0.9 yet). Only a site above the target may
             do it: never a site itself, a sibling or a site below (a branch cannot grant itself). Granting a role to
             the target's own `<target>-admins` marks the group (GRANT_MARK), so convergence keeps it; revoking it
             clears the mark. A role group the target made itself (owned by its own agent, OU admins or admins: one it
             deleted and made again) is deleted and made again here, empty, first; and a missing one is made (2.1.9.21,
             revised 2026-10-13): the way back from convergence's refusal (manual 4.9.1.2). A grant is refused unless
             the person, or every person in the group (nested too), lives at the target or a site above it (2.1.9.24).
    Inputs:  samdb — SamDB (as the site's agent: AD refuses a write outside its site's OU too); lp — LoadParm
             (unused); site — str, this install's site (the one granting); target — str, the site the role is at;
             role — one of site_roles.grantable(); member — a group or person name ("" for `<target>-admins`);
             grant — bool, True to grant, False to revoke.
    Returns: {"site": target, "role", "group", "member", "granted" (bool), "changed" (bool), "remade" (bool: a group
             the target had made was replaced)}.
    Fails:   ValueError "<role> is not a role a site can be granted (…)", "only a site above <target> may grant its
             roles…", "no group or person …", "<uid> lives at …" (placement_refusal); ValueError from alloc_id;
             LookupError for an unknown site; ldb.LdbError (ERR_INSUFFICIENT_ACCESS_RIGHTS outside the agent's site).
    Feeds:   directory_ops (op "grant_site_role")."""
    if role not in grantable():
        raise ValueError(f"{role} is not a role a site can be granted ({', '.join(grantable())})")
    if target not in paths.below(samdb, site):
        raise ValueError(f"only a site above {target} may grant its roles: {site} is not above it"
                         + (" (a site cannot grant itself)" if target == site else ""))
    member = member or f"{target}-admins"
    who = _member_dn(samdb, member)
    if grant:                   # who may hold a role at the target: people living there or above (2.1.9.24)
        people = [who] if _is_person(samdb, who) else [
            str(m.dn) for m in samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE, attrs=["dn"],
                                            expression=f"(&(objectCategory=person)(objectClass=user)"
                                                       f"(memberOf:{IN_CHAIN}:={ldb.binary_encode(who)}))")]
        for dn in people:
            why = placement_refusal(samdb, dn, [target])
            if why:
                raise ValueError(why)
    name = grant_group(target, role)
    groups = f"OU=groups,{paths.site_dn(samdb, target)}"
    res = find_group(samdb, groups, name)
    remade = bool(res) and branch_made(samdb, target, str(res[0].dn))
    if remade:                  # never kept: its members and permissions are the branch's own
        samdb.delete(str(res[0].dn))
        res = []
    if not res:
        make_group(samdb, target, role, name, groups)
        res = find_group(samdb, groups, name)
    have = who.lower() in [str(m).lower() for m in res[0].get("member", [])]
    mark = str(res[0].get("adminDescription", [""])[0]) == GRANT_MARK
    admins = member == f"{target}-admins"
    if admins and grant and not mark:       # marked first: a convergence between the two steps keeps the grant
        samdb.modify(ldb.Message.from_dict(samdb, {"dn": str(res[0].dn), "adminDescription": GRANT_MARK},
                                           ldb.FLAG_MOD_REPLACE))
    if have != grant:
        samdb.add_remove_group_members(name, [member], add_members_operation=grant)
    if admins and not grant and mark:
        msg = ldb.Message(res[0].dn)
        msg["adminDescription"] = ldb.MessageElement([], ldb.FLAG_MOD_DELETE, "adminDescription")
        samdb.modify(msg)
    return {"site": target, "role": role, "group": name, "member": member, "granted": grant,
            "changed": have != grant or remade, "remade": remade}
