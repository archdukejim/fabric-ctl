"""A site's role groups as a site above handles them (2.1.9.21, manual 1.6.3.18.4): found, recognised as one the
site made itself, made again. Shared by grant_site_role and remake_site_group."""
import ldb

from acl_entries import owner_of, sid_of
from alloc_id import alloc_id
import paths
from site_roles import CONSOLE_ROLES, FABRIC_ADMINS, ROLES

HOST_ADMINS = "Manage the site's hosts: root through sudo, fabricctl (manual 1.6.11)"   # as ensure_groups says it


def find_group(samdb, groups, name):
    """Purpose: a group in a site's OU=groups.
    Inputs:  samdb — SamDB; groups — the OU=groups DN; name — sAMAccountName.
    Returns: list of ldb.Message (member, adminDescription), empty when there is none.
    Fails:   ldb.LdbError from the search.
    Feeds:   grant_site_role, remake_site_group."""
    return list(samdb.search(base=groups, scope=ldb.SCOPE_ONELEVEL, attrs=["member", "adminDescription"],
                             expression=f"(&(objectClass=group)(sAMAccountName={ldb.binary_encode(name)}))"))


def branch_made(samdb, target, dn):
    """Purpose: whether the target site itself made a group (its agent, OU admins or admins own it): one it deleted and
             made again, which convergence refuses (ensure_site_acl, 2.1.9.21 revised 2026-10-13).
    Inputs:  samdb — SamDB; target — the site; dn — the group's DN.
    Returns: bool.
    Fails:   ldb.LdbError reading a security descriptor; IndexError if one of the site's principals is missing.
    Feeds:   grant_site_role, remake_site_group."""
    return owner_of(samdb, dn) in {sid_of(samdb, n) for n in (f"fabric-agent-{target}", f"{target}-ou-admins",
                                                              f"{target}-admins")}


def make_group(samdb, target, role, name, groups):
    """Purpose: a role's group made in the target's OU=groups, empty, as ensure_groups makes it: a console role's
             without a gid; an AD role's, the host admins' and the site's admins' with a gid from the site's block; the
             host admins with the organisation's `fabric-admins` in it; the site's admins in `<target>-users` (so
             Keycloak admits them, 2.1.9.21).
    Inputs:  samdb — SamDB (as a site above's agent); target — the site; role — str ("admins" for `<target>-admins`);
             name — the group's name; groups — the OU=groups DN.
    Returns: None.
    Fails:   ldb.LdbError from a change; ValueError from alloc_id (the block's range full).
    Feeds:   grant_site_role, remake_site_group."""
    description = (CONSOLE_ROLES[role][1] if role in CONSOLE_ROLES else
                   "" if role == "admins" else ROLES.get(role, HOST_ADMINS))
    samdb.newgroup(name, groupou=paths.relative(samdb, groups), description=description or None)
    if role in CONSOLE_ROLES:
        return
    gid = alloc_id(samdb, paths.site_dn(samdb, target), "builtin_group")
    samdb.modify(ldb.Message.from_dict(samdb, {"dn": f"CN={name},{groups}", "gidNumber": str(gid)},
                                       ldb.FLAG_MOD_REPLACE))
    if role == FABRIC_ADMINS:
        samdb.add_remove_group_members(name, [FABRIC_ADMINS], add_members_operation=True)
    if role == "admins" and find_group(samdb, groups, f"{target}-users"):
        samdb.add_remove_group_members(f"{target}-users", [name], add_members_operation=True)
