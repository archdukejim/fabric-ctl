import ldb

import paths
from site_roles import OLD_SUDO_ROLE, fabric_admins, role_group


def _has_group(samdb, name):
    """Purpose: whether a group exists, anywhere in the domain.
    Inputs:  samdb — SamDB; name — sAMAccountName.
    Returns: bool.
    Fails:   ldb.LdbError from the search.
    Feeds:   legacy_logon_groups (during a federation's upgrade)."""
    return bool(samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE,
                             expression=f"(&(objectClass=group)(sAMAccountName={ldb.binary_encode(name)}))",
                             attrs=["dn"]))


def legacy_logon_groups(samdb, site, admin_group):
    """Purpose: the groups a site's machines grant log-on to while it has no per-OU policies (`logon_policies` null:
             every install before 0.9, which an upgrade keeps, 2.1.6.44; manual 1.6.11.4): the site's people and
             admins, the console's admin group, fabric-break-glass, the windows-admins role of the site and of every
             site above it, the site's fabric-admins, the fabric-admins (or, before their upgrade, the linux-sudo role)
             of the sites above, and their admins.
    Inputs:  samdb — SamDB (as the system or the site's agent: reads only); site — str; admin_group — the web
             console's admin group.
    Returns: list of str, group names in a stable order (the GPO's SIDs follow it).
    Fails:   LookupError from paths (no such site); ldb.LdbError from a search.
    Feeds:   ensure_logon_policies (the site's legacy GPO), logon_groups (the editor's first edit makes it the site
             OU's policy)."""
    owners = [site] + paths.ancestors(samdb, site)
    names = [f"{site}-users", f"{site}-admins", admin_group, "fabric-break-glass"]
    names += [role_group(o, "windows-admins") for o in owners] + [fabric_admins(site)]
    # a site above that has not converged since the upgrade still has its linux-sudo role: whichever it has (1.6.11.3)
    names += [g for o in owners[1:] for g in (fabric_admins(o), f"{o}-{OLD_SUDO_ROLE}") if _has_group(samdb, g)]
    names += [f"{o}-admins" for o in owners[1:]]
    return names
