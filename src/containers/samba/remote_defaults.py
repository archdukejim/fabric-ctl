import paths
from site_roles import CLASSES, FABRIC_ADMINS, fabric_admins


def remote_defaults(samdb, site, machine_class):
    """Purpose: who a site's `<site>-<class>-remote-users` holds when it is made (decision 2.1.7.14 as revised
             2026-10-13, the owner's layered model): central IT — the organisation's `fabric-admins` and the root
             site's `<root>-admins` — in both, at every site; the site's own `<site>-fabric-admins` in its server
             group; the site's `<site>-admins` in its desktop group. A site above adds more by granting the role.
    Inputs:  samdb — SamDB; site — str; machine_class — a key of site_roles.CLASSES.
    Returns: list of group names, central IT first, without repeats (the root site's two coincide in its own).
    Fails:   KeyError for an unknown class; LookupError from paths.ancestors for an unknown site.
    Feeds:   ensure_groups, role_groups.make_group (a group a site above makes again gets it too)."""
    CLASSES[machine_class]
    root = ([site] + paths.ancestors(samdb, site))[-1]
    local = fabric_admins(site) if machine_class == "server" else f"{site}-admins"
    out = []
    for name in (FABRIC_ADMINS, f"{root}-admins", local):
        if name not in out:
            out.append(name)
    return out
