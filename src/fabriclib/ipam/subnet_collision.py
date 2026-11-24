import ipaddress


def subnet_collision(cidr, fabric_subnet, plan_subnets, moving=None):
    """Purpose: what a new LAN subnet collides with (manual 1.3.7.7, decision 2.1.1.107; global Rule 9): fabric's
             own container network, or a subnet of the address plan, other than the LAN subnet that moves with it.
    Inputs:  cidr — the new subnet; fabric_subnet — fabric's container network (str), or None when not known;
             plan_subnets — kept_plan_subnets()'s list, or None when not known; moving — the old LAN subnet, which the
             plan moves to the new one (1.3.7.7), or None.
    Returns: str, the collision in words; "" when there is none.
    Fails:   ValueError for a network that is not one (callers check the form first).
    Feeds:   backup/check_changes, move/check_new_address."""
    net = ipaddress.ip_network(str(cidr), strict=False)
    if fabric_subnet:
        own = ipaddress.ip_network(str(fabric_subnet), strict=False)
        if net.overlaps(own):
            return f"{net} overlaps fabric's container network {own} (fabric_subnet)"
    old = ipaddress.ip_network(str(moving), strict=False) if moving else None
    for s in plan_subnets or []:
        other = ipaddress.ip_network(str(s["cidr"]), strict=False)
        if old is not None and other == old:
            continue
        if net.overlaps(other):
            return f"{net} overlaps {other} ({s.get('name') or 'a subnet'}) of the address plan"
    return ""
