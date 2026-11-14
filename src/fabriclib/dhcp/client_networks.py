from fabriclib.ipam.planned_subnets import planned_subnets


def client_networks(v):
    """Purpose: the networks of DHCP's clients and fabric's addresses facing them (manual 1.10.3.3): where fabric
             listens on a served interface. What each network may reach is the site's access rules' (1.10.4.48); the
             guest split (2.1.10.4) is parked (2.1.10.58), so every subnet is "full" and "guest" stays empty.
    Inputs:  v — rendered vars: install_kea; dhcp.subnets [{subnet, access ("full" default, or "guest"), server
             (fabric's address for them, set by place_subnets)}], or without dhcp.subnets the plan this site last read
             (planned_subnets, manual 1.10.4.14).
    Returns: {"full": [subnet, ...], "guest": [subnet, ...], "full_addrs": [address, ...], "guest_addrs":
             [address, ...]}: each list deduplicated, in subnet order; all empty when DHCP is off.
    Fails:   OSError or json errors reading a damaged plan copy.
    Feeds:   dns/builtin_acls, dns_filter (the resolver's clients, check_filter_groups), security/firewall_rules,
             security/apply_docker_firewall, deploy/check_settings (dhcp_served for the templates)."""
    out = {"full": [], "guest": [], "full_addrs": [], "guest_addrs": []}
    if not v.get("install_kea"):
        return out
    for s in planned_subnets(v):
        kind = "full"                     # a VLAN's access is no longer read (2.1.10.58): the rules decide (1.10.4.48)
        for key, value in ((kind, s.get("subnet")), (f"{kind}_addrs", s.get("server"))):
            if value and value not in out[key]:
                out[key].append(value)
    return out
