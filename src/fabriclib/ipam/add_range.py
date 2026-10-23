from fabriclib.ipam.check_range import check_range
from fabriclib.ipam.common.edit_plan import edit_plan
from fabriclib.ipam.common.fields import find_vlan, ipv4, subnet_holding


def add_range(v, actor, vid, kind, first, last, site="", notes="", secrets=None, container="samba", source="cli",
              caller=None):
    """Purpose: a range added to a VLAN's subnet (manual 1.10.4.3, 1.10.4.16): gateway, static, dhcp (Kea's pool) or
             reserved, under check_range's rules; of a VLAN with several subnets, the one holding its first address
             (2.1.10.18). A dhcp range is served at the next apply of the site.
    Inputs:  v — fabric vars; actor — who asks (audit); vid — the VLAN ID; kind — the range's kind; first, last —
             addresses; site — whose plan ("" this site's); notes — text; secrets, container, source, caller — as
             edit_plan.
    Returns: edit_plan's result; result = the range {"kind", "first", "last", "notes"}.
    Fails:   ValidationError: no such VLAN, a VLAN without a subnet, a first address in none of its subnets, what
             check_range or edit_plan refuses.
    Feeds:   run_ipam_command (range add)."""
    def change(plan, read, org):
        vlan, subs = find_vlan(plan, vid)
        sub = subnet_holding(vlan, subs, ipv4(first, "first address"), "first address")
        rng = check_range({"kind": kind, "first": first, "last": last, "notes": notes}, sub)
        changes = [{"do": "add", "what": "range", "site": plan["site"], "subnet": sub["name"],
                    "key": f"{rng['kind']}-{rng['first']}", "fields": rng}]
        return changes, rng, f"vlan={vlan['id']} {rng['kind']} {rng['first']}-{rng['last']}", []
    return edit_plan(v, actor, site, "IPAM_RANGE_ADD", change, secrets, container, source, caller=caller)
