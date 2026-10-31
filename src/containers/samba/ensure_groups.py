import ldb

from alloc_id import alloc_id
from group_names import DOMAIN_GROUPS, rodc_cache, site_group
import paths

DOMAIN_USERS_RID = 513          # AD's Domain Users: fabric's everyone-group `users` (Q11)


def _group(samdb, name):
    """Purpose: a group by name, anywhere in the domain.
    Inputs:  samdb — SamDB; name — sAMAccountName.
    Returns: the ldb.Message (dn, gidNumber, description), or None.
    Fails:   ldb.LdbError from the search.
    Feeds:   _ensure."""
    res = samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE,
                       expression=f"(&(objectClass=group)(sAMAccountName={ldb.binary_encode(name)}))",
                       attrs=["gidNumber", "description"])
    return res[0] if res else None


def _ensure(samdb, name, ou, gid, description, done):
    """Purpose: one group as wanted: created in its OU when missing; its gid number and description set when they
             differ (a gid from the DC's range is taken only for a group that has none).
    Inputs:  samdb — SamDB; name — str; ou — str, relative to the domain; gid — int, a callable giving one when
             the group has none, or None (not a POSIX group: no gid, none taken); description — str or ""; done —
             list, what changed is appended.
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


def ensure_groups(samdb, dc, site, root, org_groups, rodc=False):
    """Purpose: the groups fabric makes (manual 1.6.13.3; 2.1.6.74, 2.1.6.81, 2.1.6.85), in OU=groups, with their gid
             numbers (1.6.3.9). At the root, first, the organisation's groups — fabric's `ldap_groups` with their fixed
             gids (`directory-admins` the console's admin group, the RBAC bundle groups, the 802.1X groups), `users` as
             AD's Domain Users — then the domain's own: `directory-admins` (when ldap_groups lacks it), `dc-hosts`,
             `fabric-managed`, `fabric-break-glass`, `server-admins`, `desktop-admins`, `network-admins` and the
             machine types' `machines-servers`, `machines-desktops`, `machines-network`. For every site its
             `site-<name>`, and for a read-only DC `rodc-cache-<dc>`, what it may cache (2.1.6.52). gids come from the
             built-in range of the converging DC's record (2.1.6.63); the cache group is not POSIX. No group is nested
             in another: who may do what comes from grants (D3).
    Inputs:  samdb — SamDB; dc — the DC whose range gids come from (the converging DC, or the one prepared); site —
             str, its site; root — bool; org_groups — list of {name, gidNumber, description?} (fabric's ldap_groups);
             rodc — bool: the DC is a read-only one.
    Returns: list of str, what changed.
    Fails:   ldb.LdbError from a creation or change; ValueError from alloc_id when the range is full.
    Feeds:   converge."""
    base = str(samdb.domain_dn())
    groups = paths.relative(samdb, paths.folder_dn(samdb, "groups"))
    done = []

    def builtin():          # fabric's own groups take gids from the DC's built-in range (2.1.6.46)
        return alloc_id(samdb, dc, "builtin_group")

    if root:                # the organisation's fixed gids first: none handed out below may take one of theirs
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
            _ensure(samdb, g["name"], groups, int(g["gidNumber"]),
                    g.get("description") or DOMAIN_GROUPS.get(g["name"], ""), done)
        named = {g["name"] for g in org_groups}
        for name, description in DOMAIN_GROUPS.items():
            if name not in named:
                _ensure(samdb, name, groups, builtin, description, done)
    _ensure(samdb, site_group(site), groups, builtin,
            f"fabric: the site {site}'s people and machines (manual 1.6.13.3)", done)
    if rodc:
        _ensure(samdb, rodc_cache(dc), groups, None,            # not POSIX: takes no id
                f"fabric: the accounts read-only DC {dc} may cache (manual 1.6.11.13)", done)
    return done
