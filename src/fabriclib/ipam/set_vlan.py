import ipaddress

from fabriclib.common.errors import ValidationError
from fabriclib.ipam.check_subnet import check_subnet
from fabriclib.ipam.check_vlan import check_vlan
from fabriclib.ipam.common.edit_plan import edit_plan
from fabriclib.ipam.common.fields import KEEP, find_vlan

SUBNET_FIELDS = ("gateway", "dhcp", "relay", "allow_overlap")


def _gateway_claim(sub):
    """Purpose: refuse a gateway another claim holds, or one Kea would hand out (manual 1.10.4.3.2).
    Inputs:  sub — the subnet's plan entry with its new gateway.
    Returns: None.
    Fails:   ValidationError naming the address or the DHCP range.
    Feeds:   set_vlan."""
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


def set_vlan(v, actor, vid, site="", name=KEEP, purpose=KEEP, notes=KEEP, access=KEEP, gateway=KEEP, dhcp=KEEP,
             relay=KEEP, allow_overlap=KEEP, secrets=None, container="samba", source="cli"):
    """Purpose: a VLAN's record changed (name, purpose, notes, access) and its subnet's settings (gateway, served by
             DHCP, relay, overlap reason) under the same rules as when it was added (manual 1.10.4.3, 1.10.4.16).
             The VLAN's ID and its subnet's network stay (remove and add to change them); renaming the VLAN keeps
             its subnet's name, which Kea and the DNS filter's groups know it by.
    Inputs:  v — fabric vars; actor — who asks (audit); vid — the VLAN ID; site — whose plan ("" this site's); name,
             purpose, notes, access — the record's new values; gateway ("" none), dhcp (bool), relay ("" none),
             allow_overlap ("" none) — the subnet's; KEEP leaves a field as it is; secrets, container, source — as
             edit_plan.
    Returns: edit_plan's result; result = {"vlan", "subnet" (None for a record only)}.
    Fails:   ValidationError: no such VLAN; nothing to change; a subnet setting for a VLAN without a subnet; what
             check_vlan or check_subnet refuses; a gateway another address claims or inside a DHCP range.
    Feeds:   run_ipam_command (vlan set)."""
    wanted = {"name": name, "purpose": purpose, "notes": notes, "access": access}
    subnet_wanted = {"gateway": gateway, "dhcp": dhcp, "relay": relay, "allow_overlap": allow_overlap}
    if all(x is KEEP for x in (*wanted.values(), *subnet_wanted.values())):
        raise ValidationError("nothing to change: give --name, --purpose, --notes, --access, --gateway, --dhcp, "
                              "--relay or --allow-overlap")

    def change(plan, read, org):
        vlan, sub = find_vlan(plan, vid)
        new = check_vlan({**vlan, **{k: x for k, x in wanted.items() if x is not KEEP}}, plan, current=vlan["id"])
        changes = [{"do": "set", "what": "vlan", "site": plan["site"], "key": str(vlan["id"]), "fields": new}]
        out = {"vlan": new, "subnet": None}
        given = {k: x for k, x in subnet_wanted.items() if x is not KEEP}
        if given and sub is None:
            raise ValidationError(f"VLAN {vlan['id']} has no subnet (a record only)")
        if given:
            checked = check_subnet({**sub, **given}, plan, plan["site"], org, v.get("fabric_subnet") or
                                   "10.255.0.0/24", current=sub["name"])
            _gateway_claim({**sub, "gateway": checked["gateway"]})
            fields = {k: checked[k] for k in SUBNET_FIELDS}
            fields["kind"] = "dhcp" if checked["dhcp"] else "subnet"
            changes.append({"do": "set", "what": "subnet", "site": plan["site"], "key": sub["name"],
                            "fields": fields})
            out["subnet"] = {**sub, **fields}
        detail = " ".join(f"{k}={x}" for k, x in {**wanted, **subnet_wanted}.items() if x is not KEEP)
        return changes, out, f"vlan={vlan['id']} {detail}", []
    return edit_plan(v, actor, site, "IPAM_VLAN_SET", change, secrets, container, source,
                     networks=any(x is not KEEP for x in subnet_wanted.values()))
