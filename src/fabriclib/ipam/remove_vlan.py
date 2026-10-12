from fabriclib.common.errors import ValidationError
from fabriclib.ipam.common.edit_plan import edit_plan
from fabriclib.ipam.common.fields import find_vlan


def remove_vlan(v, actor, vid, site="", force=False, secrets=None, container="samba", source="cli"):
    """Purpose: a VLAN removed from a site's plan with its subnet, the subnet's ranges and its addresses (manual
             1.10.4.16). A subnet that still records addresses is kept unless forced, so nothing recorded goes by
             accident; its live leases end at their expiry once Kea no longer serves it.
    Inputs:  v — fabric vars; actor — who asks (audit); vid — the VLAN ID; site — whose plan ("" this site's);
             force — remove the recorded addresses too; secrets, container, source — as edit_plan.
    Returns: edit_plan's result; result = {"vlan", "subnet" (its network or None), "addresses" (how many went)}.
    Fails:   ValidationError: no such VLAN; addresses recorded in its subnet without force (how many); what
             edit_plan refuses.
    Feeds:   run_ipam_command (vlan remove)."""
    def change(plan, read, org):
        vlan, sub = find_vlan(plan, vid)
        held = len(sub.get("addresses") or []) if sub else 0
        if held and not force:
            raise ValidationError(f"VLAN {vlan['id']}'s subnet {sub['cidr']} records {held} address(es): remove them "
                                  "first, or give --force to remove them with it")
        changes = []
        if sub:
            changes.append({"do": "remove", "what": "subnet", "site": plan["site"], "key": sub["name"]})
        changes.append({"do": "remove", "what": "vlan", "site": plan["site"], "key": str(vlan["id"])})
        out = {"vlan": vlan, "subnet": sub["cidr"] if sub else None, "addresses": held}
        return changes, out, f"vlan={vlan['id']} subnet={out['subnet']} addresses={held}", []
    return edit_plan(v, actor, site, "IPAM_VLAN_REMOVE", change, secrets, container, source)
