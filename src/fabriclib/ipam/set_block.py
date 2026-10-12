from fabriclib.common.errors import ValidationError
from fabriclib.ipam.check_block import check_block
from fabriclib.ipam.common.edit_plan import edit_plan


def set_block(v, actor, number, site="", secrets=None, container="samba", source="cli"):
    """Purpose: a site's number set or changed (manual 1.10.4.13.4, 2.1.10.16): `fabricctl ipam block <n>` and setup's
             question. The number shapes only what fabric suggests from then on (`10.<n>.<VLAN>.0/24`); subnets
             already in the plan keep their networks.
    Inputs:  v — fabric vars (site_name); actor — who asks (audit); number — int or str; site — whose number ("" this
             site's; a site above may number a site below it); secrets, container, source — as edit_plan.
    Returns: edit_plan's result; result = {"block": the number, "was": the number before or None}.
    Fails:   ValidationError: what check_block refuses; the number the site already has (nothing to change); what
             edit_plan refuses (a site AD does not let this site's agent write: "not permitted").
    Feeds:   run_ipam_command (block), setup/ask_site_number."""
    def change(plan, read, org):
        n = check_block(number, read["sites"], plan["site"])
        if n == plan["block"]:
            raise ValidationError(f"nothing to change: site {plan['site']}'s number is already {n}")
        changes = [{"do": "set", "what": "block", "site": plan["site"], "fields": {"block": n}}]
        return changes, {"block": n, "was": plan["block"]}, f"block={n} was={plan['block']}", []
    return edit_plan(v, actor, site, "IPAM_BLOCK_SET", change, secrets, container, source)
