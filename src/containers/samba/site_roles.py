"""The roles that administer a site (2.1.9.13, manual 1.6.3.6): each its own group in the site's OU=groups, so each can
be given to a different admin group. Since 0.9 (2.1.9.21, manual 1.6.3.18) `<site>-admins` is in none of them by
default: it is the site's helpdesk, and a site above grants it (or any group) more roles. A parent site's AD roles reach
the sites below it (2.1.6.20); a console role gives its bundle at its own site only (1.6.8.2)."""

# role -> what its group's description says
ROLES = {
    "ou-admins": "Manage the site's OU: people, groups and sub-OUs",
    "machine-admins": "Add, enable and remove the site's machines and devices",
    "gpo-admins": "Edit the site's own Group Policy, and block what a parent did not enforce",
    "windows-admins": "Local Administrators on the site's Windows machines",
}


# the console roles a site above may grant at a site (2.1.9.21, manual 1.6.8.2): role -> (Keycloak bundle, description).
# Their groups are not POSIX groups (no gid from the site's block).
CONSOLE_ROLES = {
    "network-operators": ("fabric-network-operator", "Network operator in the site's web console: DNS, DHCP"),
    "equipment-operators": ("fabric-equipment-operator", "Equipment operator in the site's console: 802.1X, devices"),
    "pki-operators": ("fabric-pki-operator", "PKI operator in the site's web console: certificates"),
    "helpdesk": ("fabric-helpdesk", "Helpdesk in the site's web console: people and their sign-in"),
    "auditors": ("fabric-auditor", "Auditor in the site's web console: reads everything, changes nothing"),
}
# what is marked on a role group that a site above granted to the site's own admins (2.1.9.21): convergence keeps
# `<site>-admins` in a role group only with this mark, so the upgrade's narrowing never undoes a grant
GRANT_MARK = "fabric: granted to the site's admins (2.1.9.21)"


# the role fabric-admins replaced (2.1.6.37): known only to the move that retires it (ensure_sudo_rule)
OLD_SUDO_ROLE = "linux-sudo"
# the organisation's host admins, and each site's (manual 1.6.11.2): host management, apart from the console's admins
FABRIC_ADMINS = "fabric-admins"


def fabric_admins(site):
    """Purpose: a site's host-admin group name (manual 1.6.11.2).
    Inputs:  site — str.
    Returns: str "<site>-fabric-admins".
    Fails:   never.
    Feeds:   ensure_groups, ensure_sudo_rule, converge."""
    return f"{site}-fabric-admins"


def rodc_cache(site):
    """Purpose: the group of a site's accounts its read-only DC may cache (decision 2.1.6.52, manual 1.6.11.13): on
             the read-only DC's password replication allow list (msDS-RevealOnDemandGroup).
    Inputs:  site — str.
    Returns: str "<site>-rodc-cache".
    Fails:   never.
    Feeds:   ensure_groups, place_fabric_host."""
    return f"{site}-rodc-cache"


def fabric_machines(site):
    """Purpose: the group of a site's machines fabric manages (manual 1.6.11.6).
    Inputs:  site — str.
    Returns: str "<site>-fabric-machines".
    Fails:   never.
    Feeds:   ensure_groups."""
    return f"{site}-fabric-machines"


def grantable():
    """Purpose: every role a site above may grant at a site (2.1.9.21): the AD roles (ROLES, and the site's host
             admins, fabric-admins) and the console roles (CONSOLE_ROLES).
    Inputs:  none.
    Returns: list of str role names, AD roles first.
    Fails:   never.
    Feeds:   grant_site_role, list_site_roles, ensure_site_acl, narrow_site_admins."""
    return list(ROLES) + [FABRIC_ADMINS] + list(CONSOLE_ROLES)


def grant_group(site, role):
    """Purpose: the group of a grantable role at a site (2.1.9.21).
    Inputs:  site — str; role — one of grantable().
    Returns: str "<site>-<role>" ("<site>-fabric-admins" for fabric-admins).
    Fails:   KeyError for a role that cannot be granted.
    Feeds:   grant_site_role, list_site_roles, ensure_site_acl, narrow_site_admins, ensure_groups."""
    if role not in grantable():
        raise KeyError(role)
    return f"{site}-{role}"


def role_group(site, role):
    """Purpose: a role's group name.
    Inputs:  site — str; role — a key of ROLES.
    Returns: str "<site>-<role>".
    Fails:   KeyError for an unknown role.
    Feeds:   ensure_groups, ensure_site_acl, ensure_sudo_rule, converge."""
    ROLES[role]
    return f"{site}-{role}"
