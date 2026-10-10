import ldb

import paths
from site_roles import FABRIC_ADMINS, OLD_SUDO_ROLE, fabric_admins

MARK = "fabric: the site's fabric-admins (2.1.6.37)"
SUDO_ROLE_MARK = "fabric: the site's linux-sudo role (2.1.9.13)"   # the rule fabric-admins replaces, moved once
OLD_MARK = "fabric: the site's admins (2.1.9.13)"      # the rule before the roles: named <site>-admins


def ensure_sudo_rule(samdb, site, admin_group, root=False):
    """Purpose: the site's default sudo rule (manual 1.6.11.3; 2.1.6.37): members of `<site>-fabric-admins` (and, at the
             root site, the organisation's `fabric-admins`) may run any command as root on the site's joined Linux
             machines, and on those of every site below it (their installer reads the rules of each site above,
             1.6.7.4). Once, on the first convergence after the upgrade: the `linux-sudo` role's members (and, at the
             root, the console admin group's, which the old rule named) are added to the fabric-admins groups, then
             its rule and group are removed, so nobody loses sudo (2.1.6.44). Other rules in OU=sudoers are the
             admins' and never touched, except fabric's own older rules.
    Inputs:  samdb — SamDB (as the system); site — str; admin_group — the web UI's admin group (sAMAccountName);
             root — bool, the root site.
    Returns: list of str, what changed.
    Fails:   ldb.LdbError for a change AD refuses (OU=sudoers missing: ensure_layout makes it first).
    Feeds:   converge."""
    sudoers = f"OU=sudoers,{paths.site_dn(samdb, site)}"
    done = []
    old = f"CN={site}-admins,{sudoers}"
    if _exists(samdb, old) and _description(samdb, old) == OLD_MARK:
        samdb.delete(old)
        done.append(f"sudo rule {site}-admins removed")
    role = f"{site}-{OLD_SUDO_ROLE}"
    previous = f"CN={role},{sudoers}"
    if _exists(samdb, previous) and _description(samdb, previous) == SUDO_ROLE_MARK:
        done += _move_members(samdb, role, fabric_admins(site))
        if root:
            done += _move_members(samdb, admin_group, FABRIC_ADMINS)
        samdb.delete(previous)
        done.append(f"sudo rule {role} removed ({fabric_admins(site)} replaces it, 2.1.6.37)")
        group = _dn_of(samdb, role)
        if group:
            samdb.delete(group)
            done.append(f"group {role} removed (its members are in {fabric_admins(site)})")
    dn = f"CN={fabric_admins(site)},{sudoers}"
    users = {f"%{fabric_admins(site)}"} | ({f"%{FABRIC_ADMINS}"} if root else set())
    want = {"sudoUser": sorted(users), "sudoHost": ["ALL"], "sudoCommand": ["ALL"], "sudoRunAsUser": ["ALL"],
            "description": [MARK]}
    found = samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=list(want)) if _exists(samdb, dn) else []
    if not found:
        samdb.add({"dn": dn, "objectClass": "sudoRole", **want})
        return done + [f"sudo rule {fabric_admins(site)} added"]
    msg = ldb.Message(found[0].dn)
    for attr, val in want.items():
        if sorted(str(x) for x in found[0].get(attr, [])) != sorted(val):
            msg[attr] = ldb.MessageElement(val, ldb.FLAG_MOD_REPLACE, attr)
    if len(msg) == 0:
        return done
    samdb.modify(msg)
    return done + [f"sudo rule {fabric_admins(site)} changed"]


def _description(samdb, dn):
    """Purpose: an entry's description.
    Inputs:  samdb — SamDB; dn — str, an existing entry.
    Returns: str ("" when it has none).
    Fails:   ldb.LdbError from the search.
    Feeds:   ensure_sudo_rule."""
    return str(samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["description"])[0].get("description", [""])[0])


def _dn_of(samdb, name):
    """Purpose: a group's DN by its name, anywhere in the domain.
    Inputs:  samdb — SamDB; name — sAMAccountName.
    Returns: str, or None when there is no such group.
    Fails:   ldb.LdbError from the search.
    Feeds:   ensure_sudo_rule, _move_members."""
    res = samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE,
                       expression=f"(&(objectClass=group)(sAMAccountName={ldb.binary_encode(name)}))", attrs=["dn"])
    return str(res[0].dn) if res else None


def _move_members(samdb, source, target):
    """Purpose: add a group's direct members (people and nested groups) to another group, so they keep what the source
             gave them; the source is left as it is.
    Inputs:  samdb — SamDB; source, target — group names (target must exist).
    Returns: list of str, what changed.
    Fails:   ldb.LdbError from the change.
    Feeds:   ensure_sudo_rule."""
    src, dst = _dn_of(samdb, source), _dn_of(samdb, target)
    if not src or not dst:
        return []
    have = {str(m).lower() for m in samdb.search(base=dst, scope=ldb.SCOPE_BASE, attrs=["member"])[0]
            .get("member", [])}
    moved = [str(m) for m in samdb.search(base=src, scope=ldb.SCOPE_BASE, attrs=["member"])[0].get("member", [])
             if str(m).lower() not in have]
    if moved:
        samdb.modify(ldb.Message.from_dict(samdb, {"dn": dst, "member": moved}, ldb.FLAG_MOD_ADD))
    return [f"group {target}: {m.split(',')[0][3:]} a member (from {source})" for m in moved]


def _exists(samdb, dn):
    """Purpose: whether an entry exists.
    Inputs:  samdb — SamDB; dn — str.
    Returns: bool.
    Fails:   ldb.LdbError other than no such object.
    Feeds:   ensure_sudo_rule."""
    try:
        samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["dn"])
        return True
    except ldb.LdbError as e:
        if e.args[0] == ldb.ERR_NO_SUCH_OBJECT:
            return False
        raise
