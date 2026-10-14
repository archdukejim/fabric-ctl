import ldb

from alloc_id import alloc_id
import paths
from remote_defaults import remote_defaults
from site_roles import CONSOLE_ROLES, FABRIC_ADMINS, REMOTE_ROLES, ROLES, fabric_admins, fabric_machines, grant_group, \
    remote_users, rodc_cache, role_group

DOMAIN_USERS_RID = 513          # AD's Domain Users: fabric's everyone-group `users` (Q11)


def _group(samdb, name):
    """Purpose: a group by name, anywhere in the domain.
    Inputs:  samdb — SamDB; name — sAMAccountName.
    Returns: the ldb.Message (dn, gidNumber, description), or None.
    Fails:   ldb.LdbError from the search.
    Feeds:   ensure_groups."""
    res = samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE,
                       expression=f"(&(objectClass=group)(sAMAccountName={ldb.binary_encode(name)}))",
                       attrs=["gidNumber", "description"])
    return res[0] if res else None


def _ensure(samdb, name, ou, gid, description, done):
    """Purpose: one group as wanted: created in its OU when missing; its gid number and description set when they
             differ (a gid from the site's block is taken only for a group that has none).
    Inputs:  samdb — SamDB; name — str; ou — str, relative to the domain; gid — int, a callable giving one when
             the group has none, or None (not a POSIX group: no gid, none taken from the block); description — str
             or ""; done — list, what changed is appended.
    Returns: None.
    Fails:   ldb.LdbError from a creation or change.
    Feeds:   ensure_groups."""
    msg = _group(samdb, name)
    if msg is None:
        samdb.newgroup(name, groupou=ou, description=description or None)
        done.append(f"group {name} created")
        msg = _group(samdb, name)
    changes = {}
    have = int(str(msg["gidNumber"][0])) if "gidNumber" in msg else None
    want = gid if isinstance(gid, int) or gid is None else (have if have is not None else gid())
    if gid is not None and have != want:
        changes["gidNumber"] = str(want)
    if description and str(msg.get("description", [""])[0]) != description:
        changes["description"] = description
    if changes:
        samdb.modify(ldb.Message.from_dict(samdb, {"dn": str(msg.dn), **changes}, ldb.FLAG_MOD_REPLACE))
        done += [f"group {name}: {k}" for k in sorted(changes)]


def _add_member(samdb, group, member, done):
    """Purpose: one group (or account) a member of another, when it is not already.
    Inputs:  samdb — SamDB; group — the containing group's name; member — the member's name; done — list, appended.
    Returns: None.
    Fails:   ldb.LdbError from the change; TypeError if the group does not exist.
    Feeds:   ensure_groups."""
    have = samdb.search(base=str(_group(samdb, group).dn), scope=ldb.SCOPE_BASE, attrs=["member"])[0]
    want = str(_group(samdb, member).dn).lower()
    if want not in [str(m).lower() for m in have.get("member", [])]:
        samdb.add_remove_group_members(group, [member], add_members_operation=True)
        done.append(f"group {group}: {member} a member")


def ensure_groups(samdb, site, root, org_groups):
    """Purpose: the groups access is built on (manual 1.6.3.6, 1.6.3.10), with their gid numbers (1.6.3.9): the site's
             people and admins, its four AD role groups (2.1.9.13) (gids from the built-in range of the site's block,
             2.1.6.46) and its console role groups (no gid: not POSIX), all empty: since 0.9 `<site>-admins` is in
             none of them unless a site above grants it (2.1.9.21; narrow_site_admins takes an older site's out), and
             at the root site, first, the organisation's groups —
             fabric's `ldap_groups` (the web UI's admin group, the RBAC bundle groups, the 802.1X groups) with their
             own gids, `users` as AD's Domain Users, and `fabric-break-glass` (in every site's log-on policy). The host
             groups (manual 1.6.11.2): the organisation's `fabric-admins` (at the root), each site's
             `<site>-fabric-admins` with `fabric-admins` in it, `<site>-fabric-machines`, and `<site>-rodc-cache`
             (what a read-only DC of the site may cache, 2.1.6.52), `<site>-server-remote-users` and
             `<site>-desktop-remote-users` (who may sign in remotely to each class of machine, 2.1.7.14); a new site's
             `<site>-fabric-admins` starts as a member of `<site>-machine-admins` (2.1.6.38), an existing site's is
             never nested by an upgrade.
    Inputs:  samdb — SamDB; site — str; root — bool; org_groups — list of {name, gidNumber, description?} (fabric's
             ldap_groups).
    Returns: list of str, what changed.
    Fails:   ldb.LdbError from a creation or change; ValueError from alloc_id when the block is full.
    Feeds:   converge."""
    base = str(samdb.domain_dn())
    site_dn = paths.site_dn(samdb, site)
    done = []
    def builtin():          # fabric's own groups take gids from the block's built-in range (2.1.6.46)
        return alloc_id(samdb, site_dn, "builtin_group")

    if root:                # the organisation's fixed gids first: none handed out below may take one of theirs
        org = paths.relative(samdb, f"OU=groups,{paths.organisation_dn(samdb)}")
        for g in org_groups:
            if g["name"] == "users":
                users = samdb.search(base=base, scope=ldb.SCOPE_SUBTREE,
                                     expression=f"(objectSid={samdb.get_domain_sid()}-{DOMAIN_USERS_RID})",
                                     attrs=["gidNumber"])[0]
                if str(users.get("gidNumber", [""])[0]) != str(g["gidNumber"]):
                    samdb.modify(ldb.Message.from_dict(samdb, {"dn": str(users.dn), "gidNumber": str(g["gidNumber"])},
                                                       ldb.FLAG_MOD_REPLACE))
                    done.append(f"Domain Users: gidNumber {g['gidNumber']} (fabric's users)")
                continue
            _ensure(samdb, g["name"], org, int(g["gidNumber"]), g.get("description") or "", done)
    groups = paths.relative(samdb, f"OU=groups,{site_dn}")
    for name in (f"{site}-users", f"{site}-admins"):
        _ensure(samdb, name, groups, builtin, "", done)
    new_site = f"group {site}-users created" in done
    for role, description in ROLES.items():      # the site's AD roles (2.1.9.13), granted from above (2.1.9.21)
        _ensure(samdb, role_group(site, role), groups, builtin, description, done)
    for role, (_, description) in CONSOLE_ROLES.items():     # the console roles a site above may grant (2.1.9.21)
        _ensure(samdb, grant_group(site, role), groups, None, description, done)
    if root:
        _ensure(samdb, "fabric-break-glass", org, builtin,
                "May log on to every site's machines: for when everything else fails", done)
        _ensure(samdb, FABRIC_ADMINS, org, builtin,
                "Manage every site's hosts: root through sudo, fabricctl (manual 1.6.11)", done)
    _ensure(samdb, fabric_admins(site), groups, builtin,
            "Manage the site's hosts: root through sudo, fabricctl (manual 1.6.11)", done)
    _ensure(samdb, fabric_machines(site), groups, builtin,
            "The site's machines fabric manages (manual 1.6.11.6)", done)
    _ensure(samdb, rodc_cache(site), groups, None,          # not POSIX: takes no id from the site's block
            "Accounts the site's read-only DC may cache: its password replication allow list (manual 1.6.11.13)", done)
    if _group(samdb, FABRIC_ADMINS) is not None:      # a site's DC converging before the root's upgrade has none yet
        _add_member(samdb, fabric_admins(site), FABRIC_ADMINS, done)
    if new_site:
        _add_member(samdb, role_group(site, "machine-admins"), fabric_admins(site), done)
    # who may sign in remotely (SSH through SSSD, RDP) to the site's machines of each class (decision 2.1.7.14 as
    # revised 2026-10-13, manual 1.6.11.9.13): made here only (convergence, as the system; never by a branch's agent),
    # the layered default nested when the group is made (an upgrade's too); a later change from above is kept
    for cls in ("server", "desktop"):
        name = remote_users(site, cls)
        _ensure(samdb, name, groups, builtin, REMOTE_ROLES[f"{cls}-remote-users"], done)
        if f"group {name} created" in done:
            for member in remote_defaults(samdb, site, cls):
                if _group(samdb, member) is not None:      # the root's not converged yet: added at its next run
                    _add_member(samdb, name, member, done)
    return done
