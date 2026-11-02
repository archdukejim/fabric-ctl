import ipaddress

from fabriclib.common.errors import ValidationError
from fabriclib.ipam.common.fields import find_address, find_subnet, find_vlan
from fabriclib.ipam.common.vlan_refs import vlan_label


def netboot_targets(plan, target):
    """Purpose: what a netboot command works on (manual 1.10.4.25): a VLAN (each of its subnets), a subnet (by name or
             network) or a reservation's address.
    Inputs:  plan — the site's plan; target — str as typed: a VLAN ID, an address, a subnet's name or network.
    Returns: list of (label, entry, write_plan change maker: function(preset or None) -> change dict).
    Fails:   ValidationError: a VLAN with no subnet; an address that is not a reservation; no such subnet or address.
    Feeds:   set_netboot, clear_netboot, show_options."""
    text = str(target or "").strip()
    if not text:
        raise ValidationError("netboot: give a VLAN, a subnet or an address")

    def subnet(s):
        return (f"subnet {s['name']}", s, lambda preset: {"do": "set", "what": "subnet", "site": plan["site"],
                                                          "key": s["name"], "fields": {"netboot": preset}})
    if text.split("@", 1)[0].isdigit():       # a VLAN: `10`, or `10@branch` at another location (1.10.4.46)
        vlan, subs = find_vlan(plan, text)
        if not subs:
            raise ValidationError(f"{vlan_label(vlan)} has no subnet in {plan['site']}'s plan")
        return [subnet(s) for s in subs]
    try:
        ipaddress.IPv4Address(text)
    except ValueError:
        return [subnet(find_subnet(plan, text))]
    addr, sub = find_address(plan, text)
    if addr["kind"] != "reservation":
        raise ValidationError(f"{addr['ip']} is a {addr['kind']} address: DHCP answers only a reservation, so only a "
                              "reservation can netboot")
    return [(f"address {addr['ip']}", addr,
             lambda preset: {"do": "set", "what": "address", "site": plan["site"], "subnet": sub["name"],
                             "key": addr["ip"], "fields": {"netboot": preset}})]
