import ipaddress

from fabriclib.common.errors import ValidationError
from fabriclib.federation.common.load_registry import load_registry


def check_new_address(v, address, registry=None):
    """Purpose: whether an address may be announced as the host's next (manual 4.2.4.1, 4.2.4.2; decision 2.1.1.79):
             an IPv4 address on the host's LAN (a move to another network is not covered), not the LAN's own network
             or broadcast address, not its gateway, not the address the host has now; on an install with no linked
             sites (2.1.1.77: a linked site is not moved).
    Inputs:  v — rendered vars (host_ip, lan_cidr, lan_gateway); address — str; registry — the federation registry
             (default: load_registry()).
    Returns: str, the address in its normal form.
    Fails:   ValidationError saying why.
    Feeds:   run_move_command."""
    try:
        new = ipaddress.IPv4Address(str(address))
    except ValueError:
        raise ValidationError(f"{address!r} is not an IPv4 address") from None
    lan = ipaddress.ip_network(v["lan_cidr"], strict=False)
    if new not in lan:
        raise ValidationError(f"{new} is not on the host's LAN ({lan}): a move to another network is not covered "
                              "(manual 4.2.4.1)")
    if new in (lan.network_address, lan.broadcast_address):
        raise ValidationError(f"{new} is the LAN's network or broadcast address")
    if str(new) == v.get("lan_gateway"):
        raise ValidationError(f"{new} is the LAN's gateway")
    if str(new) == v["host_ip"]:
        raise ValidationError(f"{new} is the host's address now: there is no move to announce")
    links = registry if registry is not None else load_registry()
    if links.get("upstream") or links.get("sites"):
        raise ValidationError("this install has linked sites: they keep its old address, and it is not moved "
                              "(manual 4.2.4.1)")
    return str(new)
