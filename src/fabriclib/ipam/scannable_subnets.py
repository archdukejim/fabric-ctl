import ipaddress

from fabriclib.ipam.planned_subnets import planned_subnets

LARGEST = 1022          # a /22's hosts: a larger network is not scanned at once (decision 2.1.10.26)


def scannable_subnets(v):
    """Purpose: the subnets an on-request scan may cover (manual 1.10.4.22, decision 2.1.10.26): only the ones this
             site's Kea serves, each no larger than a /22.
    Inputs:  v — fabric vars (install_kea, dhcp; the plan this site last read, through planned_subnets).
    Returns: list of {"name", "cidr", "vlan", "hosts"} in address order ([] with DHCP off).
    Fails:   OSError or json errors reading a damaged plan copy (planned_subnets).
    Feeds:   scan_subnet; agent GET /v1/ipam/scan (the console's scan page)."""
    if not v.get("install_kea"):
        return []
    out = []
    for s in planned_subnets(v):
        net = ipaddress.ip_network(str(s.get("subnet")), strict=False)
        hosts = net.num_addresses - 2 if net.prefixlen < 31 else net.num_addresses
        if hosts <= LARGEST:
            out.append({"name": s.get("name") or "", "cidr": str(net), "vlan": s.get("vlan") or "", "hosts": hosts})
    return sorted(out, key=lambda s: ipaddress.ip_network(s["cidr"]))
