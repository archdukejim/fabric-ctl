from fabriclib.ipam.rules.access_sources import access_sources


def builtin_acls(data):
    """Purpose: The ACLs fabric always renders (vars.yaml.j2 merges user entries over them), so they and their entries
             cannot be removed.
    Inputs:  data — the vars dict; reads fabric_subnet (default 10.255.0.0/24) and the networks the site's access
             rules allow dns (access_sources, manual 1.10.4.48.3).
    Returns: {"acme-updaters": [subnet], "dns-resolvers": ["127.0.0.1", subnet, *the networks allowed dns]}.
    Fails:   OSError or json errors reading a damaged plan copy (access_sources).
    Feeds:   remove_acl_entries (refuses to remove them), run_acl_command (marks them "built in" in `acl list`).
    """
    subnet = data.get("fabric_subnet") or "10.255.0.0/24"
    return {
        "acme-updaters": [subnet],
        "dns-resolvers": list(dict.fromkeys(["127.0.0.1", subnet, *access_sources(data)["dns"]])),
    }
