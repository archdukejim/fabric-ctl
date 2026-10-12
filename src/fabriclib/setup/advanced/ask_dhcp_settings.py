import ipaddress

from fabriclib.common.ask import ask
from fabriclib.common.console import NC, YELLOW
from fabriclib.common.errors import ValidationError
from fabriclib.dhcp.normalize_dhcp import normalize_dhcp
from fabriclib.dhcp.place_subnets import place_subnets
from fabriclib.system.host_networks import host_networks


def _suggested_pool(cidr):
    """Purpose: a pool to offer for a subnet: the upper half of its addresses, short of the last ten.
    Inputs:  cidr — the subnet (str).
    Returns: "first - last", or "" for a subnet too small to offer one.
    Fails:   never (a subnet that does not parse gives "").
    Feeds:   ask_dhcp_settings."""
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
        return ""
    if net.num_addresses < 32:
        return ""
    first = net.network_address + net.num_addresses // 2
    return f"{first} - {net.broadcast_address - 10}"


def ask_dhcp_settings(ctx, networks=None):
    """Purpose: what turning DHCP on needs when it has no settings yet, asked as `fabricctl dhcp on` takes them (manual
             1.10.3.5): the interface to serve, the subnet, a pool and the router, checked the same way
             (normalize_dhcp, place_subnets).
    Inputs:  ctx — SetupContext: vars (dhcp, host_ip, lan_cidr, lan_gateway; changed); networks — host_networks()
             (None: this host's). Interactive.
    Returns: True with ctx.vars["dhcp"] set to the checked settings; False when they were refused (the reason printed,
             nothing changed) — the item stays off.
    Fails:   EOFError from input().
    Feeds:   setup/advanced/ask_part (DHCP turned on)."""
    v = ctx.vars
    networks = host_networks() if networks is None else networks
    on_lan = next((i for i, addrs in networks.items() for a in addrs if str(a.ip) == str(v.get("host_ip"))), "")
    iface = ask("setup.dhcp.interface", f"    Interface to serve ({', '.join(sorted(networks)) or 'none found'}) "
                f"[{on_lan}]: ", on_lan)
    subnet = ask("setup.dhcp.subnet", f"    Subnet to serve [{v.get('lan_cidr') or ''}]: ", v.get("lan_cidr") or "")
    pool = ask("setup.dhcp.pool", f"    Pool, 'first - last' [{_suggested_pool(subnet)}]: ", _suggested_pool(subnet))
    router = ask("setup.dhcp.router", f"    Router told to clients [{v.get('lan_gateway') or ''}]: ",
                 v.get("lan_gateway") or "")
    try:
        if router:
            ipaddress.IPv4Address(router)
        first = {"subnet": subnet, "pools": [pool], **({"routers": router} if router else {})}
        dhcp = {**(v.get("dhcp") or {}), "interfaces": [iface], "subnets": [first]}
        dhcp = normalize_dhcp({**v, "dhcp": dhcp, "install_kea": True})
        place_subnets(dhcp, v.get("host_ip"), networks)
    except (ValidationError, ValueError) as e:
        print(f"    {YELLOW}refused: {e}; DHCP stays off{NC}")
        return False
    v["dhcp"] = dhcp
    return True
