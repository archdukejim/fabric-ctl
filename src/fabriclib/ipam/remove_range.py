from fabriclib.common.errors import ValidationError
from fabriclib.ipam.common.edit_plan import edit_plan
from fabriclib.ipam.common.fields import find_vlan, ipv4
from fabriclib.ipam.common.vlan_refs import vlan_label, vlan_ref


def remove_range(v, actor, vid, first, site="", secrets=None, container="samba", source="cli",
                 caller=None):
    """Purpose: a range removed from one of a VLAN's subnets, named by its first address (manual 1.10.4.16); the
             addresses recorded in it stay. Removing a dhcp range stops Kea handing out its addresses at the site's
             next apply.
    Inputs:  v — fabric vars; actor — who asks (audit); vid — the VLAN (`<id>`, or `<id>@<location>`); first — the
             range's first address; site — whose plan ("" this site's); secrets, container, source, caller — as
             edit_plan.
    Returns: edit_plan's result; result = the range removed.
    Fails:   ValidationError: no such VLAN, no range of its subnets starting at that address; what edit_plan refuses.
    Feeds:   ipam/cli/run_plan_change (range remove), agent/post_networks."""
    start = str(ipv4(first, "first address"))

    def change(plan, read, org):
        vlan, subs = find_vlan(plan, vid)
        found = next(((s, r) for s in subs for r in s.get("ranges") or [] if r["first"] == start), None)
        if found is None:
            raise ValidationError(f"{vlan_label(vlan)} has no range starting at {start}")
        sub, rng = found
        changes = [{"do": "remove", "what": "range", "site": plan["site"], "subnet": sub["name"],
                    "key": f"{rng['kind']}-{rng['first']}"}]
        return changes, rng, f"vlan={vlan_ref(vlan)} {rng['kind']} {rng['first']}-{rng['last']}", []
    return edit_plan(v, actor, site, "IPAM_RANGE_REMOVE", change, secrets, container, source, caller=caller)
