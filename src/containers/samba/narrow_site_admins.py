import ldb

from site_roles import FABRIC_ADMINS, GRANT_MARK, ROLES, grant_group

WHY = "2.1.9.21: a site's admins are its helpdesk; a site above grants more"


def _group(samdb, name):
    """Purpose: a group's DN, its direct members and its grant mark, by name, anywhere in the domain.
    Inputs:  samdb — SamDB; name — sAMAccountName.
    Returns: (dn str, [member DN str lower-cased], adminDescription str), or None when there is no such group.
    Fails:   ldb.LdbError from the search.
    Feeds:   narrow_site_admins."""
    res = samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE,
                       expression=f"(&(objectClass=group)(sAMAccountName={ldb.binary_encode(name)}))",
                       attrs=["member", "adminDescription"])
    if not res:
        return None
    return (str(res[0].dn), [str(m).lower() for m in res[0].get("member", [])],
            str(res[0].get("adminDescription", [""])[0]))


def narrow_site_admins(samdb, site, root, admin_group):
    """Purpose: a site's admins narrowed to the site helpdesk (2.1.9.21, manual 1.6.3.18): `<site>-admins` taken out of
             the site's AD role groups (ou-admins, machine-admins, gpo-admins, windows-admins) and its host admins
             (`<site>-fabric-admins`, where 0.9's move from linux-sudo put it), unless a site above granted that role
             to it (the group carries GRANT_MARK). At the root site the organisation's admin group (Central IT) is
             kept in the root's four AD role groups, which reach every site (2.1.6.20): its rights stay what they
             were through `<root>-admins`. Runs at every convergence, for the converging site and every site below
             it (a site whose own DC is read-only, or not upgraded yet, is narrowed from above); a group not there yet
             is skipped. The site's admins are also nested in `<site>-users` (revision of 2026-10-13), so Keycloak,
             which admits `<site>-users` (ensure_ldap_federation), admits them and they get the site helpdesk's
             console.
    Inputs:  samdb — SamDB (as the system); site — str; root — bool, the root site (the organisation's admins);
             admin_group — the organisation's admin group (webui_admin_group).
    Returns: list of str, what changed (each says why: the change log of the upgrade).
    Fails:   ldb.LdbError from a search or a membership change.
    Feeds:   converge."""
    done = []
    admins = _group(samdb, f"{site}-admins")
    org = _group(samdb, admin_group) if root else None
    for role in list(ROLES) + [FABRIC_ADMINS]:
        name = grant_group(site, role)
        group = _group(samdb, name)
        if group is None:
            continue
        _, members, mark = group
        if admins is not None and admins[0].lower() in members and mark != GRANT_MARK:
            samdb.add_remove_group_members(name, [f"{site}-admins"], add_members_operation=False)
            done.append(f"group {name}: {site}-admins removed ({WHY})")
        if org is not None and role in ROLES and org[0].lower() not in members:
            samdb.add_remove_group_members(name, [admin_group], add_members_operation=True)
            done.append(f"group {name}: {admin_group} a member (Central IT keeps every site, 2.1.9.21)")
    users = _group(samdb, f"{site}-users")
    if admins is not None and users is not None and admins[0].lower() not in users[1]:
        samdb.add_remove_group_members(f"{site}-users", [f"{site}-admins"], add_members_operation=True)
        done.append(f"group {site}-users: {site}-admins a member (2.1.9.21: a site's admins sign in to its console)")
    return done
