from fabriclib.common.errors import ValidationError
from fabriclib.ipam.common.change_subnet import change_subnet
from fabriclib.ipam.common.edit_plan import edit_plan
from fabriclib.ipam.common.fields import KEEP, find_subnet


def set_subnet(v, actor, which, site="", gateway=KEEP, dhcp=KEEP, relay=KEEP, notes=KEEP, allow_overlap=KEEP,
               secrets=None, container="samba", source="cli",
               caller=None):
    """Purpose: one subnet's settings changed (manual 1.10.4.16, 2.1.10.18): its gateway, served by DHCP or not, relay,
             notes and overlap reason, under the rules it was added with (common/change_subnet). Its name, network
             and VLAN stay (remove and add to change them).
    Inputs:  v — fabric vars; actor — who asks (audit); which — the subnet's name or network; site — whose plan (""
             this site's); gateway ("" none), dhcp (bool), relay ("" none), notes, allow_overlap ("" none) — new
             values, KEEP leaves one as it is; secrets, container, source, caller — as edit_plan.
    Returns: edit_plan's result; result = the subnet as it will be.
    Fails:   ValidationError: nothing to change; no such subnet; what check_subnet refuses; a gateway another
             address claims or inside a DHCP range; what edit_plan refuses.
    Feeds:   run_ipam_command (subnet set)."""
    wanted = {"gateway": gateway, "dhcp": dhcp, "relay": relay, "notes": notes, "allow_overlap": allow_overlap}
    given = {k: x for k, x in wanted.items() if x is not KEEP}
    if not given:
        raise ValidationError("nothing to change: give --gateway, --dhcp, --relay, --notes or --allow-overlap")

    def change(plan, read, org):
        sub = find_subnet(plan, which)
        sub_change, new = change_subnet(v, plan, org, sub, given)
        detail = " ".join(f"{k}={x}" for k, x in given.items())
        return [sub_change], new, f"subnet={sub['name']} {detail}", []
    return edit_plan(v, actor, site, "IPAM_SUBNET_SET", change, secrets, container, source, networks=True,
                     caller=caller)
