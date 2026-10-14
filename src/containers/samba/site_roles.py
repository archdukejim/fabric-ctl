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


# a machine's class (decision 2.1.7.14, second revision; 2.1.6.36's revision): what remote access follows, not its OS.
# class -> its OU below the site's OU=machines (each holding OU=linux and OU=windows)
CLASSES = {"server": "servers", "desktop": "desktops"}
# the remote-users roles (2.1.7.14 as revised 2026-10-13): role -> its group's description. Granted only from above,
# like the site's AD roles (2.1.9.21): grantable() lists them, so a branch's own agent is denied writing them and a
# site above grants, revokes and remakes them (a remade one gets remote_defaults' nesting again)
REMOTE_ROLES = {f"{cls}-remote-users": f"May sign in remotely (SSH, RDP) to the site's {cls}s (manual 1.6.11.9.13)"
                for cls in CLASSES}


def remote_users(site, machine_class):
    """Purpose: the group of who may sign in remotely (SSH through SSSD, RDP) to a site's machines of one class
             (decision 2.1.7.14, revised 2026-10-13; manual 1.6.11.9.13).
    Inputs:  site — str; machine_class — a key of CLASSES.
    Returns: str "<site>-server-remote-users" or "<site>-desktop-remote-users" (grant_group's name for the role).
    Fails:   KeyError for an unknown class.
    Feeds:   ensure_groups, ensure_logon_policies, ssh_user_sites."""
    CLASSES[machine_class]
    return f"{site}-{machine_class}-remote-users"


def grantable():
    """Purpose: every role a site above may grant at a site (2.1.9.21): the AD roles (ROLES, and the site's host
             admins, fabric-admins), the console roles (CONSOLE_ROLES) and the remote-users roles (REMOTE_ROLES,
             2.1.7.14 as revised 2026-10-13).
    Inputs:  none.
    Returns: list of str role names, AD roles first.
    Fails:   never.
    Feeds:   grant_site_role, list_site_roles, ensure_site_acl, narrow_site_admins, role_groups."""
    return list(ROLES) + [FABRIC_ADMINS] + list(CONSOLE_ROLES) + list(REMOTE_ROLES)


def grant_group(site, role):
    """Purpose: the group of a grantable role at a site (2.1.9.21).
    Inputs:  site — str; role — one of grantable().
    Returns: str "<site>-<role>" ("<site>-fabric-admins" for fabric-admins; "<site>-server-remote-users" is
             remote_users(site, "server")).
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


# the class a machine gets when nobody names one (2.1.6.36's revision): by its OS family, Linux machines are servers
# (a Linux desktop says so at its join, join-linux.sh --class desktop) and Windows ones desktops (a Windows Server is
# sorted by its operatingSystem, sort_windows_machines)
DEFAULT_CLASS = {"linux": "server", "windows": "desktop"}


def class_of(dn):
    """Purpose: a machine's class read from where its account sits (2.1.6.36's revision, manual 1.6.11.5): the class
             OU above it below OU=machines.
    Inputs:  dn — the computer account's DN (str).
    Returns: "server", "desktop", or "" (in no class OU: OU=machines itself, OU=fabric-hosts, elsewhere).
    Fails:   never.
    Feeds:   list_machines, set_machine_class."""
    parts = [p.strip().lower() for p in str(dn).split(",")]
    for i, part in enumerate(parts[:-1]):
        if parts[i + 1] == "ou=machines":
            for cls, ou in CLASSES.items():
                if part == f"ou={ou}":
                    return cls
    return ""
