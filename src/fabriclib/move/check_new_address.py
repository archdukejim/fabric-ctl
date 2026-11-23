import ipaddress

from fabriclib.common.errors import ValidationError
from fabriclib.federation.common.load_registry import load_registry
from fabriclib.ipam.kept_plan_subnets import kept_plan_subnets
from fabriclib.ipam.subnet_collision import subnet_collision


def check_new_address(v, address, registry=None, network=None, plans=None):
    """Purpose: whether an address may be announced as the host's next (manual 4.2.4.1, 4.2.4.2, 4.2.4.8; decision
             2.1.1.79, revised 2026-11-19): an IPv4 address on the host's LAN, or on the other network named for a
             move to another VLAN and subnet; not that network's own network or broadcast address, not the LAN's
             gateway, not the address the host has now; on an install with no linked sites (2.1.1.77: a linked site
             is not moved); another network colliding with nothing fabric holds (fabric's container network, the
             address plan's other subnets: subnet_collision, 2.1.1.107).
    Inputs:  v — rendered vars (host_ip, lan_cidr, lan_gateway); address — str; registry — the federation registry
             (default: load_registry()); network — the new network for a move off the LAN (`--network`), or None;
             plans — kept_plan_subnets()'s list (default: read it).
    Returns: str, the address in its normal form.
    Fails:   ValidationError saying why.
    Feeds:   run_move_command."""
    try:
        new = ipaddress.IPv4Address(str(address))
    except ValueError:
        raise ValidationError(f"{address!r} is not an IPv4 address") from None
    lan = ipaddress.ip_network(v["lan_cidr"], strict=False)
    if network is not None:
        try:
            net = ipaddress.IPv4Network(str(network), strict=False)
        except ValueError:
            raise ValidationError(f"--network {network!r} is not an IPv4 network like 10.0.20.0/24") from None
        if net.overlaps(lan):
            raise ValidationError(f"--network {net} is the host's LAN ({lan}) or overlaps it: give the address alone")
        if new not in net:
            raise ValidationError(f"{new} is not in --network {net}")
        found = subnet_collision(net, v.get("fabric_subnet") or "10.255.0.0/24",
                                 kept_plan_subnets() if plans is None else plans, moving=v["lan_cidr"])
        if found:
            raise ValidationError(f"--network {net} collides: {found}. Choose another subnet for the host's LAN")
        lan = net
    elif new not in lan:
        raise ValidationError(f"{new} is not on the host's LAN ({lan}): for another VLAN and subnet give its network, "
                              f"`fabricctl move prepare {new} --network <new subnet>` (manual 4.2.4.8)")
    if new in (lan.network_address, lan.broadcast_address):
        raise ValidationError(f"{new} is the network or broadcast address of {lan}")
    if str(new) == v.get("lan_gateway"):
        raise ValidationError(f"{new} is the LAN's gateway")
    if str(new) == v["host_ip"]:
        raise ValidationError(f"{new} is the host's address now: there is no move to announce")
    links = registry if registry is not None else load_registry()
    if links.get("upstream") or links.get("sites"):
        raise ValidationError("this install has linked sites: they keep its old address, and it is not moved "
                              "(manual 4.2.4.1)")
    return str(new)
