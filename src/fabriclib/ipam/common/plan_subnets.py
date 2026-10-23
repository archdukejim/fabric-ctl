import ipaddress

from fabriclib.ipam.common.plan_cache import load_plan_cache
from fabriclib.ipam.planned_subnets import planned_subnets


def plan_subnets(v, cache=load_plan_cache):
    """Purpose: every subnet of this site's plan, DHCP on or off, with the ones DHCP serves (decision 2.1.10.28, manual
             1.10.4.27.1): the plan this site last read (1.10.4.14) and, before the upgrade, 0.7's `dhcp.subnets`.
    Inputs:  v — fabric vars (site_name, dhcp); cache — function() -> the kept plan or None (load_plan_cache; tests
             give their own).
    Returns: list of {"name", "cidr", "vlan" (int or ""), "dhcp" (bool: Kea serves it), "hosts" (int), "entry" (its
             dhcp.subnets form when Kea serves it, else {}: the reservations and router a site not yet upgraded keeps
             there)}, in address order, each network once.
    Fails:   OSError or json errors reading a damaged plan copy.
    Feeds:   scan_subnet."""
    found = {}
    for s in planned_subnets(v):
        net = ipaddress.ip_network(str(s.get("subnet")), strict=False)
        found[str(net)] = {"name": str(s.get("name") or ""), "cidr": str(net), "vlan": s.get("vlan") or "",
                           "dhcp": True, "entry": s}
    plan = cache()
    if plan and plan.get("site", v.get("site_name")) == v.get("site_name"):
        for s in plan.get("subnets") or []:
            net = ipaddress.ip_network(str(s.get("cidr")), strict=False)
            found.setdefault(str(net), {"name": str(s.get("name") or ""), "cidr": str(net),
                                        "vlan": s.get("vlan") or "", "dhcp": bool(s.get("dhcp")), "entry": {}})
    for s in found.values():
        net = ipaddress.ip_network(s["cidr"])
        s["hosts"] = net.num_addresses - 2 if net.prefixlen < 31 else net.num_addresses
    return sorted(found.values(), key=lambda s: ipaddress.ip_network(s["cidr"]))
