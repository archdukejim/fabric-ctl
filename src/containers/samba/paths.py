"""The DNs of the directory's folders (manual 1.6.13.2, 2.1.6.72, 2.1.6.80): one set for the whole domain, fixed, made
by ensure_layout; and fabric's own state in `CN=fabric,CN=System` (2.1.6.79)."""
import ldb


# the folders under the domain, each fabric's and marked so (1.6.13.2); OU=fabric inside OU=groups and one OU per
# machine type inside OU=machines are made with them
FOLDERS = ("people", "service-accounts", "groups", "machines", "fabric-hosts", "devices", "device-roles", "networks",
           "sudoers")
# a machine's type -> its OU under OU=machines and its group, machines-<OU> (1.6.13.3)
MACHINE_TYPES = {"server": "servers", "desktop": "desktops", "network": "network"}


def folder_dn(samdb, name):
    """Purpose: one of the domain's folders (1.6.13.2).
    Inputs:  samdb — SamDB; name — one of FOLDERS.
    Returns: str "OU=<name>,<domain>".
    Fails:   ValueError for a name that is not one of the folders.
    Feeds:   the directory operations and converge's parts."""
    if name not in FOLDERS:
        raise ValueError(f"not one of the directory's folders: {name}")
    return f"OU={name},{samdb.domain_dn()}"


def computed_groups_dn(samdb):
    """Purpose: where the grants' computed groups go (1.6.13.4): OU=fabric inside OU=groups.
    Inputs:  samdb — SamDB.
    Returns: str "OU=fabric,OU=groups,<domain>".
    Fails:   never.
    Feeds:   ensure_layout, ensure_directory_acl."""
    return f"OU=fabric,{folder_dn(samdb, 'groups')}"


def machine_type_dn(samdb, kind):
    """Purpose: the OU fabric files a machine of a type in (1.6.13.3).
    Inputs:  samdb — SamDB; kind — a key of MACHINE_TYPES (server, desktop, network).
    Returns: str, e.g. "OU=servers,OU=machines,<domain>".
    Fails:   ValueError for an unknown type.
    Feeds:   ensure_layout, create_machine, sort_windows_machines."""
    if kind not in MACHINE_TYPES:
        raise ValueError(f"not a machine type ({', '.join(MACHINE_TYPES)}): {kind}")
    return f"OU={MACHINE_TYPES[kind]},{folder_dn(samdb, 'machines')}"


def fabric_dn(samdb):
    """Purpose: fabric's own state, beside AD's (2.1.6.79): readable by every authenticated account, written by
             fabric's agent accounts.
    Inputs:  samdb — SamDB.
    Returns: str "CN=fabric,CN=System,<domain>".
    Fails:   never.
    Feeds:   ensure_layout, ensure_directory_acl."""
    return f"CN=fabric,CN=System,{samdb.domain_dn()}"


def dc_record_dn(samdb, dc):
    """Purpose: a DC's record (2.1.6.79): its id range, the ranges' marks and its site.
    Inputs:  samdb — SamDB; dc — the DC's name (dc-NNNN).
    Returns: str "CN=<dc>,CN=dcs,CN=fabric,CN=System,<domain>".
    Fails:   never.
    Feeds:   ensure_dc_record, alloc_id, dc_info."""
    return f"CN={dc},CN=dcs,{fabric_dn(samdb)}"


def relative(samdb, dn):
    """Purpose: a DN without the domain's own part, as samba's newuser, newgroup and newcomputer take their container.
    Inputs:  samdb — SamDB; dn — str, inside the domain.
    Returns: str, e.g. "OU=people".
    Fails:   ValueError when dn is not inside the domain.
    Feeds:   create_person, create_machine, ensure_service_accounts, ensure_groups, create_host_group."""
    suffix = "," + str(samdb.domain_dn())
    if not dn.lower().endswith(suffix.lower()):
        raise ValueError(f"{dn}: not inside {suffix[1:]}")
    return dn[:-len(suffix)]


def sites_dn(samdb):
    """Purpose: where the sites' records live (2.1.10.34, manual 1.10.4.32): one per site, its number and options.
    Inputs:  samdb — SamDB.
    Returns: str "CN=sites,CN=fabric,CN=System,<domain>".
    Fails:   never.
    Feeds:   ensure_layout, site_record_dn, read_plan."""
    return f"CN=sites,{fabric_dn(samdb)}"


def site_record_dn(samdb, site):
    """Purpose: one site's record (2.1.10.34): `CN=<site>` inside CN=sites, the name escaped whatever it holds.
    Inputs:  samdb — SamDB; site — the site's name (its AD site's).
    Returns: ldb.Dn.
    Fails:   never.
    Feeds:   ensure_site_record, write_plan."""
    dn = ldb.Dn(samdb, f"CN=x,{sites_dn(samdb)}")
    dn.set_component(0, "CN", str(site))
    return dn


def domain_options_dn(samdb):
    """Purpose: the domain's DHCP option set, every site's Kea rendered with it first (2.1.10.34, manual 1.10.4.32).
    Inputs:  samdb — SamDB.
    Returns: str "CN=dhcp-options,CN=fabric,CN=System,<domain>".
    Fails:   never.
    Feeds:   ensure_domain_options, read_plan, write_plan."""
    return f"CN=dhcp-options,{fabric_dn(samdb)}"


def plan_entry_dn(samdb, site, name, below=None):
    """Purpose: an entry of the address plan in the domain's OU=networks (2.1.10.35, manual 1.10.4.33): a subnet
             `CN=<site>/<name>`, a VLAN `CN=<site>/vlan/<id>` (name "vlan/<id>"), or, with `below`, a range, an
             address or a scan request `CN=<below>` inside its subnet's entry; every name escaped.
    Inputs:  samdb — SamDB; site — str; name — the subnet's name, or "vlan/<id>"; below — the inner entry's name, or
             None.
    Returns: ldb.Dn.
    Fails:   never.
    Feeds:   write_plan, write_scan_request."""
    dn = ldb.Dn(samdb, f"CN=x,{folder_dn(samdb, 'networks')}")
    dn.set_component(0, "CN", f"{site}/{name}")
    if below is None:
        return dn
    inner = ldb.Dn(samdb, f"CN=x,{dn}")
    inner.set_component(0, "CN", str(below))
    return inner
