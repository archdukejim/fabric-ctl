from fabriclib.common.errors import ValidationError
from fabriclib.ipam.common.edit_plan import edit_plan
from fabriclib.ipam.common.fields import find_subnet


def remove_subnet(v, actor, which, site="", force=False, secrets=None, container="samba", source="cli",
                  caller=None):
    """Purpose: one subnet removed from a site's plan with its ranges and addresses (manual 1.10.4.16, 2.1.10.18); its
             VLAN stays (a record only once its last subnet goes). A subnet that still records addresses is kept
             unless forced; its live leases end at their expiry once Kea no longer serves it.
    Inputs:  v — fabric vars; actor — who asks (audit); which — the subnet's name or network; site — whose plan (""
             this site's); force — remove the recorded addresses too; secrets, container, source, caller — as edit_plan.
    Returns: edit_plan's result; result = {"subnet" (the plan entry), "addresses" (how many went)}.
    Fails:   ValidationError: no such subnet; addresses recorded without force (how many); what edit_plan refuses.
    Feeds:   run_ipam_command (subnet remove), dhcp/run_dhcp_alias (remove-subnet)."""
    def change(plan, read, org):
        sub = find_subnet(plan, which)
        held = len(sub.get("addresses") or [])
        if held and not force:
            raise ValidationError(f"subnet {sub['name']} ({sub['cidr']}) records {held} address(es): remove them "
                                  "first, or give --force to remove them with it")
        changes = [{"do": "remove", "what": "subnet", "site": plan["site"], "key": sub["name"]}]
        return changes, {"subnet": sub, "addresses": held}, f"subnet={sub['name']} {sub['cidr']} addresses={held}", []
    return edit_plan(v, actor, site, "IPAM_SUBNET_REMOVE", change, secrets, container, source, caller=caller)
