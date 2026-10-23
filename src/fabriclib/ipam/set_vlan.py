from fabriclib.common.errors import ValidationError
from fabriclib.ipam.check_vlan import check_vlan
from fabriclib.ipam.common.change_subnet import change_subnet
from fabriclib.ipam.common.edit_plan import edit_plan
from fabriclib.ipam.common.fields import KEEP, find_vlan


def set_vlan(v, actor, vid, site="", name=KEEP, purpose=KEEP, notes=KEEP, access=KEEP, gateway=KEEP, dhcp=KEEP,
             relay=KEEP, allow_overlap=KEEP, secrets=None, container="samba", source="cli", caller=None):
    """Purpose: a VLAN's record changed (name, purpose, notes, access) and, for a VLAN with one subnet, that subnet's
             settings (gateway, served by DHCP, relay, overlap reason) under the same rules as when it was added
             (manual 1.10.4.3, 1.10.4.16). A VLAN with several subnets has each changed by `subnet set` (2.1.10.18).
             The VLAN's ID and its subnets' networks stay (remove and add to change them); renaming the VLAN keeps
             its subnets' names, which Kea and the DNS filter's groups know them by.
    Inputs:  v — fabric vars; actor — who asks (audit); vid — the VLAN ID; site — whose plan ("" this site's); name,
             purpose, notes, access — the record's new values; gateway ("" none), dhcp (bool), relay ("" none),
             allow_overlap ("" none) — the subnet's; KEEP leaves a field as it is; secrets, container, source,
             caller — as edit_plan.
    Returns: edit_plan's result; result = {"vlan", "subnet" (None unless a subnet setting changed)}.
    Fails:   ValidationError: no such VLAN; nothing to change; a subnet setting for a VLAN without a subnet or with
             several (naming them); what check_vlan or check_subnet refuses; a gateway another address claims or
             inside a DHCP range.
    Feeds:   ipam/cli/run_plan_change (vlan set), agent/post_networks."""
    wanted = {"name": name, "purpose": purpose, "notes": notes, "access": access}
    subnet_wanted = {"gateway": gateway, "dhcp": dhcp, "relay": relay, "allow_overlap": allow_overlap}
    if all(x is KEEP for x in (*wanted.values(), *subnet_wanted.values())):
        raise ValidationError("nothing to change: give --name, --purpose, --notes, --access, --gateway, --dhcp, "
                              "--relay or --allow-overlap")

    def change(plan, read, org):
        vlan, subs = find_vlan(plan, vid)
        new = check_vlan({**vlan, **{k: x for k, x in wanted.items() if x is not KEEP}}, plan, current=vlan["id"])
        changes = [{"do": "set", "what": "vlan", "site": plan["site"], "key": str(vlan["id"]), "fields": new}]
        out = {"vlan": new, "subnet": None}
        given = {k: x for k, x in subnet_wanted.items() if x is not KEEP}
        if given and not subs:
            raise ValidationError(f"VLAN {vlan['id']} has no subnet (a record only)")
        if given and len(subs) > 1:
            raise ValidationError(f"VLAN {vlan['id']} has {len(subs)} subnets (" + ", ".join(s["name"] for s in subs)
                                  + "): change each with fabricctl ipam subnet set <name>")
        if given:
            sub_change, out["subnet"] = change_subnet(v, plan, org, subs[0], given)
            changes.append(sub_change)
        detail = " ".join(f"{k}={x}" for k, x in {**wanted, **subnet_wanted}.items() if x is not KEEP)
        return changes, out, f"vlan={vlan['id']} {detail}", []
    return edit_plan(v, actor, site, "IPAM_VLAN_SET", change, secrets, container, source,
                     networks=any(x is not KEEP for x in subnet_wanted.values()), caller=caller)
