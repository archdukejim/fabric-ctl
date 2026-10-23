import ipaddress

from fabriclib.common.errors import ValidationError
from fabriclib.ipam.check_subnet import check_subnet

SUBNET_FIELDS = ("gateway", "dhcp", "relay", "notes", "allow_overlap")


def _gateway_claim(sub):
    """Purpose: refuse a gateway another claim holds, or one Kea would hand out (manual 1.10.4.3.2).
    Inputs:  sub — the subnet's plan entry with its new gateway.
    Returns: None.
    Fails:   ValidationError naming the address or the DHCP range.
    Feeds:   change_subnet."""
    if not sub.get("gateway"):
        return
    gw = ipaddress.ip_address(sub["gateway"])
    taken = next((a for a in sub.get("addresses") or [] if a["ip"] == sub["gateway"]), None)
    if taken:
        raise ValidationError(f"{gw} is already claimed: a {taken['kind']} address"
                              + (f" ({taken['name']})" if taken.get("name") else ""))
    for r in sub.get("ranges") or []:
        if r["kind"] == "dhcp" and ipaddress.ip_address(r["first"]) <= gw <= ipaddress.ip_address(r["last"]):
            raise ValidationError(f"the gateway {gw} lies in the DHCP range {r['first']} - {r['last']}")


def change_subnet(v, plan, org, sub, given):
    """Purpose: the change to one subnet's settings (its gateway, served by DHCP, relay, notes, overlap reason) under
             the rules it was added with (manual 1.10.4.16): check_subnet again, and a gateway no address claims and
             no DHCP range holds. Its name and network stay (remove and add to change them).
    Inputs:  v — fabric vars (fabric_subnet); plan — the site's plan; org — every site's networks
             (read_address_plan); sub — the subnet's plan entry; given — {field: new value} of SUBNET_FIELDS.
    Returns: (the write_plan change, the subnet as it will be).
    Fails:   ValidationError from check_subnet, or a gateway another address claims or inside a DHCP range.
    Feeds:   set_vlan, set_subnet."""
    checked = check_subnet({**sub, **given}, plan, plan["site"], org, v.get("fabric_subnet") or "10.255.0.0/24",
                           current=sub["name"])
    _gateway_claim({**sub, "gateway": checked["gateway"]})
    fields = {k: checked[k] for k in SUBNET_FIELDS if k in given}
    fields["kind"] = "dhcp" if checked["dhcp"] else "subnet"
    change = {"do": "set", "what": "subnet", "site": plan["site"], "key": sub["name"], "fields": fields}
    return change, {**sub, **fields}
