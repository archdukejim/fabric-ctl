"""The names of the groups fabric makes (manual 1.6.13.3, 2.1.6.74, 2.1.6.81, 2.1.6.85): the tiers', the machine
types', the sites', fabric's managed machines and a read-only DC's cache, all in OU=groups."""
from paths import MACHINE_TYPES

DIRECTORY_ADMINS = "directory-admins"   # the Directory Administrators (1.6.12.2): the console's admin group too
DC_HOSTS = "dc-hosts"                   # the hosts that run a DC (1.6.13.6)
FABRIC_MANAGED = "fabric-managed"       # the machines fabric manages (1.6.11.6)
BREAK_GLASS = "fabric-break-glass"
TYPE_ADMINS = ("server-admins", "desktop-admins", "network-admins")    # empty; their grants are D3's (2.1.6.74)
TIERS = (DIRECTORY_ADMINS, DC_HOSTS)    # the tiers' groups: outside the Directory Administrators' rights (2.1.6.76)
# the domain-wide groups fabric makes at the root, with what each one's description says
DOMAIN_GROUPS = {
    DIRECTORY_ADMINS: "fabric: the Directory Administrators (manual 1.6.12.2)",
    DC_HOSTS: "fabric: the hosts that run a domain controller (manual 1.6.13.6)",
    FABRIC_MANAGED: "fabric: the machines fabric manages (manual 1.6.11.6)",
    BREAK_GLASS: "fabric: break glass (manual 1.6.12.10)",
    "server-admins": "fabric: the servers' administrators (manual 1.6.13.5)",
    "desktop-admins": "fabric: the desktops' administrators (manual 1.6.13.5)",
    "network-admins": "fabric: the network machines' administrators (manual 1.6.13.5)",
    **{f"machines-{ou}": f"fabric: every {kind} machine (manual 1.6.13.3)" for kind, ou in MACHINE_TYPES.items()},
}


def site_group(site):
    """Purpose: a site's group, its people and machines (2.1.6.72, 2.1.6.81).
    Inputs:  site — str.
    Returns: str "site-<site>".
    Fails:   never.
    Feeds:   ensure_groups, create_person, create_machine, adopt_linux_machines."""
    return f"site-{site}"


def type_group(kind):
    """Purpose: a machine type's group (1.6.13.3).
    Inputs:  kind — a key of paths.MACHINE_TYPES (server, desktop, network).
    Returns: str, e.g. "machines-servers".
    Fails:   KeyError for an unknown type.
    Feeds:   create_machine, sort_windows_machines."""
    return f"machines-{MACHINE_TYPES[kind]}"


def rodc_cache(dc):
    """Purpose: the group of accounts a read-only DC may cache (2.1.6.52, 2.1.6.85): on its password replication allow
             list (msDS-RevealOnDemandGroup).
    Inputs:  dc — the read-only DC's name (dc-NNNN).
    Returns: str "rodc-cache-<dc>".
    Fails:   never.
    Feeds:   ensure_groups, place_fabric_host."""
    return f"rodc-cache-{dc}"
