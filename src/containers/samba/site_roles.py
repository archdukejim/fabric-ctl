"""The roles that administer a site (2.1.9.13, manual 1.6.3.6): each its own group in the site's OU=groups, so each can
be given to a different admin group; `<site>-admins` is a member of all of them. A parent site's roles reach the sites
below it (2.1.6.20)."""

# role -> what its group's description says
ROLES = {
    "ou-admins": "Manage the site's OU: people, groups and sub-OUs",
    "machine-admins": "Add, enable and remove the site's machines and devices",
    "gpo-admins": "Edit the site's own Group Policy, and block what a parent did not enforce",
    "windows-admins": "Local Administrators on the site's Windows machines",
}


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


def role_group(site, role):
    """Purpose: a role's group name.
    Inputs:  site — str; role — a key of ROLES.
    Returns: str "<site>-<role>".
    Fails:   KeyError for an unknown role.
    Feeds:   ensure_groups, ensure_site_acl, ensure_sudo_rule, converge."""
    ROLES[role]
    return f"{site}-{role}"
