"""What fabric suggests for a site's plan (manual 1.10.4.3.3): suggestions only, never enforced."""
import ipaddress


def suggest_subnet(block, vlan_id):
    """Purpose: the subnet fabric offers a new VLAN (manual 1.10.4.3.3, 2.1.10.9, 2.1.10.12): `10.<site>.<VLAN>.0/24`,
             the site's number its second octet and the VLAN ID its third. A suggestion only, never enforced.
    Inputs:  block — the site's number (1-255) or None; vlan_id — int.
    Returns: str (e.g. "10.1.20.0/24"), or None when the site has no number or the VLAN ID does not fit an octet
             (above 255).
    Fails:   never.
    Feeds:   add_vlan."""
    if not block or not 1 <= int(block) <= 255 or not 0 <= int(vlan_id) <= 255:
        return None
    return f"10.{int(block)}.{int(vlan_id)}.0/24"


def suggest_split(cidr):
    """Purpose: the ranges fabric offers inside a new subnet (manual 1.10.4.3.3): in a /24 the gateway `.1`, static
             `.2-.99`, DHCP `.100-.249`, reserved `.250-.254`; in any other size only the gateway, its first host.
             Editable afterwards (range add and remove).
    Inputs:  cidr — str, an IPv4 network.
    Returns: {"gateway": str or "", "ranges": [{"kind", "first", "last", "notes"}]}.
    Fails:   ValueError for a cidr that is not a network.
    Feeds:   add_vlan."""
    net = ipaddress.ip_network(cidr)
    if net.prefixlen > 30:
        return {"gateway": "", "ranges": []}
    base = net.network_address
    if net.prefixlen != 24:
        return {"gateway": str(base + 1), "ranges": []}
    split = (("gateway", 1, 1), ("static", 2, 99), ("dhcp", 100, 249), ("reserved", 250, 254))
    return {"gateway": str(base + 1),
            "ranges": [{"kind": k, "first": str(base + a), "last": str(base + b), "notes": ""} for k, a, b in split]}


def suggest_block(sites, site):
    """Purpose: the number fabric offers a site (manual 1.10.4.10, 2.1.10.12): its order in the organisation (the
             sites by when their records were made in CN=sites, 1.10.4.32; the first 1), or the next number no other
             site has when that one is taken; numbers run 1-255 (an octet).
    Inputs:  sites — read_plan's "sites" [{"name", "created", "block"}], in the organisation's order; site — str.
    Returns: int, or None when every number is taken.
    Fails:   never.
    Feeds:   add_vlan and move_subnets_to_plan (a site without a number), show (the suggestion),
             setup/ask_site_number."""
    taken = {s["block"] for s in sites if s.get("block") and s["name"] != site}
    names = [s["name"] for s in sites]
    first = names.index(site) + 1 if site in names else len(names) + 1
    for n in list(range(first, 256)) + list(range(1, first)):
        if n not in taken:
            return n
    return None
