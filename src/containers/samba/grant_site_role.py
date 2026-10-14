import ldb

from acl_entries import owner_of, sid_of
from alloc_id import alloc_id
import paths
from site_roles import CONSOLE_ROLES, FABRIC_ADMINS, GRANT_MARK, ROLES, grant_group, grantable

HOST_ADMINS = "Manage the site's hosts: root through sudo, fabricctl (manual 1.6.11)"   # as ensure_groups says it


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


def _find(samdb, groups, name):
    """Purpose: a role's group in the target's OU=groups.
    Inputs:  samdb — SamDB; groups — the OU=groups DN; name — sAMAccountName.
    Returns: list of ldb.Message (member, adminDescription), empty when there is none.
    Fails:   ldb.LdbError from the search.
    Feeds:   grant_site_role."""
    return list(samdb.search(base=groups, scope=ldb.SCOPE_ONELEVEL, attrs=["member", "adminDescription"],
                             expression=f"(&(objectClass=group)(sAMAccountName={ldb.binary_encode(name)}))"))


def _branch_made(samdb, target, dn):
    """Purpose: whether the target site itself made a role group (its agent, OU admins or admins own it): a group it
             deleted and made again, which convergence refuses (ensure_site_acl, 2.1.9.21 revised 2026-10-13).
    Inputs:  samdb — SamDB; target — the site; dn — the group's DN.
    Returns: bool.
    Fails:   ldb.LdbError reading a security descriptor; IndexError if one of the site's principals is missing.
    Feeds:   grant_site_role."""
    return owner_of(samdb, dn) in {sid_of(samdb, n) for n in (f"fabric-agent-{target}", f"{target}-ou-admins",
                                                              f"{target}-admins")}


def _make(samdb, target, role, name, groups):
    """Purpose: a role's group made in the target's OU=groups, empty: a console role's without a gid; an AD role's
             and the host admins' with a gid from the site's block (as ensure_groups makes them), the host admins with
             the organisation's `fabric-admins` in it.
    Inputs:  samdb — SamDB (as a site above's agent); target — the site; role — str; name — the group's name; groups —
             the OU=groups DN.
    Returns: None.
    Fails:   ldb.LdbError from a change; ValueError from alloc_id (the block's range full).
    Feeds:   grant_site_role."""
    description = CONSOLE_ROLES[role][1] if role in CONSOLE_ROLES else ROLES.get(role, HOST_ADMINS)
    samdb.newgroup(name, groupou=paths.relative(samdb, groups), description=description)
    if role in CONSOLE_ROLES:
        return
    gid = alloc_id(samdb, paths.site_dn(samdb, target), "builtin_group")
    samdb.modify(ldb.Message.from_dict(samdb, {"dn": f"CN={name},{groups}", "gidNumber": str(gid)},
                                       ldb.FLAG_MOD_REPLACE))
    if role == FABRIC_ADMINS:
        samdb.add_remove_group_members(name, [FABRIC_ADMINS], add_members_operation=True)


def grant_site_role(samdb, lp, site, target, role, member="", grant=True):
    """Purpose: a role at a site below granted to a group or person, or taken back (2.1.9.21, manual 1.9.8.20): the
             member put in, or taken out of, the role's group `<target>-<role>` in the target's OU=groups (a console
             role's group made there first if the target has not converged 0.9 yet). Only a site above the target may
             do it: never a site itself, a sibling or a site below (a branch cannot grant itself). Granting a role to
             the target's own `<target>-admins` marks the group (GRANT_MARK), so convergence keeps it; revoking it
             clears the mark. A role group the target made itself (owned by its own agent, OU admins or admins: one it
             deleted and made again) is deleted and made again here, empty, first; and a missing one is made (2.1.9.21,
             revised 2026-10-13): the way back from convergence's refusal (manual 4.9.1.2).
    Inputs:  samdb — SamDB (as the site's agent: AD refuses a write outside its site's OU too); lp — LoadParm
             (unused); site — str, this install's site (the one granting); target — str, the site the role is at;
             role — one of site_roles.grantable(); member — a group or person name ("" for `<target>-admins`);
             grant — bool, True to grant, False to revoke.
    Returns: {"site": target, "role", "group", "member", "granted" (bool), "changed" (bool), "remade" (bool: a group
             the target had made was replaced)}.
    Fails:   ValueError "<role> is not a role a site can be granted (…)", "only a site above <target> may grant its
             roles…", "no group or person …"; ValueError from alloc_id; LookupError for an unknown
             site; ldb.LdbError (ERR_INSUFFICIENT_ACCESS_RIGHTS outside the agent's site).
    Feeds:   directory_ops (op "grant_site_role")."""
    if role not in grantable():
        raise ValueError(f"{role} is not a role a site can be granted ({', '.join(grantable())})")
    if target not in paths.below(samdb, site):
        raise ValueError(f"only a site above {target} may grant its roles: {site} is not above it"
                         + (" (a site cannot grant itself)" if target == site else ""))
    member = member or f"{target}-admins"
    who = _member_dn(samdb, member)
    name = grant_group(target, role)
    groups = f"OU=groups,{paths.site_dn(samdb, target)}"
    res = _find(samdb, groups, name)
    remade = bool(res) and _branch_made(samdb, target, str(res[0].dn))
    if remade:                  # never kept: its members and permissions are the branch's own
        samdb.delete(str(res[0].dn))
        res = []
    if not res:
        _make(samdb, target, role, name, groups)
        res = _find(samdb, groups, name)
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
