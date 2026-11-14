from fabriclib.ipam.rules.service_sources import NO_PLAN, service_sources


def dhcp_allowed(subnets, v, plan):
    """Purpose: the DHCP subnets Kea serves under the site's rules (manual 1.10.4.48.3, decision 2.1.10.54): a subnet
             whose VLAN is not allowed `dhcp` is left out of Kea's configuration, so a request from it selects no
             subnet and Kea says nothing (its raw sockets pass by the firewall).
    Inputs:  subnets — plan_to_dhcp's subnets ([{"subnet", ...}]); v — fabric vars (host_ip, lan_cidr); plan — the
             site's plan the rules come from (None: the copy last read).
    Returns: the entries allowed, in their order.
    Fails:   OSError or json errors reading a damaged plan copy.
    Feeds:   ipam/load_address_plan (an apply, the plan poll), ipam/planned_subnets."""
    allowed = set(service_sources(v, NO_PLAN if plan is None else plan)["dhcp"])
    return [s for s in subnets if s.get("subnet") in allowed]
