from fabriclib.common.errors import ValidationError
from fabriclib.ipam.common.edit_plan import edit_plan
from fabriclib.ipam.common.fields import find_vlan


def remove_vlan(v, actor, vid, site="", force=False, secrets=None, container="samba", source="cli"):
    """Purpose: a VLAN removed from a site's plan with its subnets, their ranges and their addresses (manual
             1.10.4.16). A VLAN whose subnets still record addresses is kept unless forced, so nothing recorded goes
             by accident; their live leases end at their expiry once Kea no longer serves them.
    Inputs:  v — fabric vars; actor — who asks (audit); vid — the VLAN ID; site — whose plan ("" this site's);
             force — remove the recorded addresses too; secrets, container, source — as edit_plan.
    Returns: edit_plan's result; result = {"vlan", "subnet" (its subnets' networks, comma-separated, or None),
             "addresses" (how many went)}.
    Fails:   ValidationError: no such VLAN; addresses recorded in its subnets without force (how many); what
             edit_plan refuses.
    Feeds:   run_ipam_command (vlan remove)."""
    def change(plan, read, org):
        vlan, subs = find_vlan(plan, vid)
        held = sum(len(s.get("addresses") or []) for s in subs)
        nets = ", ".join(s["cidr"] for s in subs) or None
        if held and not force:
            raise ValidationError(f"VLAN {vlan['id']}'s subnet {nets} records {held} address(es): remove them "
                                  "first, or give --force to remove them with it")
        changes = [{"do": "remove", "what": "subnet", "site": plan["site"], "key": s["name"]} for s in subs]
        changes.append({"do": "remove", "what": "vlan", "site": plan["site"], "key": str(vlan["id"])})
        out = {"vlan": vlan, "subnet": nets, "addresses": held}
        return changes, out, f"vlan={vlan['id']} subnet={nets} addresses={held}", []
    return edit_plan(v, actor, site, "IPAM_VLAN_REMOVE", change, secrets, container, source)
