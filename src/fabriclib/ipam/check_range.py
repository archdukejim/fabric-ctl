import ipaddress

from fabriclib.common.errors import ValidationError
from fabriclib.ipam.common.fields import RANGE_KINDS, host_in, ipv4, notes


def check_range(rng, subnet):
    """Purpose: a range of a subnet checked against the model's rules (manual 1.10.4.3): a kind (gateway, static, dhcp,
             reserved), first and last hosts of the subnet in order, never overlapping another of its ranges; a dhcp
             range (Kea's pool) may hold only reservations, so one over a static address or the gateway is refused.
    Inputs:  rng — {"kind", "first", "last", "notes"}; subnet — the subnet's plan entry (read_plan: cidr, gateway,
             ranges, addresses).
    Returns: the range normalized: {"kind", "first", "last" (str), "notes"}.
    Fails:   ValidationError: an unknown kind, an address that is not a host of the subnet, first after last, an overlap
             with another range (named), a dhcp range over an address that is not a reservation or over the gateway.
    Feeds:   add_range, add_vlan (the suggested split)."""
    kind = str(rng.get("kind") or "").strip().lower()
    if kind not in RANGE_KINDS:
        raise ValidationError(f"range kind {rng.get('kind')!r}: one of {', '.join(RANGE_KINDS)}")
    net = ipaddress.ip_network(subnet["cidr"])
    lo, hi = ipv4(rng.get("first"), "first address"), ipv4(rng.get("last"), "last address")
    host_in(lo, net, "first address")
    host_in(hi, net, "last address")
    if lo > hi:
        raise ValidationError(f"range {lo} - {hi}: the first address comes before the last")
    for other in subnet.get("ranges") or []:
        a, b = ipaddress.ip_address(other["first"]), ipaddress.ip_address(other["last"])
        if lo <= b and a <= hi:
            raise ValidationError(f"range {lo} - {hi} overlaps the {other['kind']} range {a} - {b}")
    if kind == "dhcp":
        for a in subnet.get("addresses") or []:
            if a["kind"] != "reservation" and lo <= ipaddress.ip_address(a["ip"]) <= hi:
                raise ValidationError(f"{a['ip']} ({a['kind']}{', ' + a['name'] if a.get('name') else ''}) lies in "
                                      f"{lo} - {hi}: a DHCP range may hold only reservations")
        if subnet.get("gateway") and lo <= ipaddress.ip_address(subnet["gateway"]) <= hi:
            raise ValidationError(f"the gateway {subnet['gateway']} lies in {lo} - {hi}: Kea would hand it out")
    return {"kind": kind, "first": str(lo), "last": str(hi), "notes": notes(rng.get("notes"))}
