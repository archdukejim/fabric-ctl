import ipaddress

from fabriclib.ipam.common.vlan_refs import vlan_ref


def _holds(cidr, address):
    """Purpose: whether a network holds an address.
    Inputs:  cidr — str; address — str.
    Returns: bool (False for anything that does not parse).
    Fails:   never.
    Feeds:   rule_networks."""
    try:
        return ipaddress.ip_address(address) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def rule_networks(v, plan):
    """Purpose: the networks a site's rules can name (manual 1.10.4.48.1): each VLAN's subnets, the host's VLAN and
             every network the site knows (`any`, 2.1.10.60).
    Inputs:  v — fabric vars (host_ip, lan_cidr); plan — the site's plan (site_plan's: vlans, subnets), or None.
    Returns: {"vlans": {"<id>" or "<id>@<location>": [CIDR, ...]}, "host": [CIDR, ...] (the subnets of the VLAN that
             holds host_ip, or [lan_cidr]), "host_vlan" (its reference, or None), "any": [CIDR, ...] (host's first,
             then every subnet, each once)}.
    Fails:   never.
    Feeds:   service_sources, check_rule, check_cut_off, rule_warnings, show_rules."""
    plan = plan or {}
    vlans = {vlan_ref(x): [] for x in plan.get("vlans") or []}
    for s in plan.get("subnets") or []:
        ref = vlan_ref({"id": s.get("vlan"), "location": s.get("location") or ""})
        if s.get("cidr") and ref in vlans and s["cidr"] not in vlans[ref]:
            vlans[ref].append(s["cidr"])
    host_ip = str(v.get("host_ip") or "")
    host_vlan = next((ref for ref, nets in vlans.items() if any(_holds(n, host_ip) for n in nets)), None)
    host = list(vlans[host_vlan]) if host_vlan else [n for n in [v.get("lan_cidr")] if n]
    every = list(host)
    for nets in vlans.values():
        every += [n for n in nets if n not in every]
    return {"vlans": vlans, "host": host, "host_vlan": host_vlan, "any": every}
