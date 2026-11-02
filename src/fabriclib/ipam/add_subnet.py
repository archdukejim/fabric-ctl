from fabriclib.ipam.common.edit_plan import edit_plan
from fabriclib.ipam.common.fields import find_vlan
from fabriclib.ipam.common.new_subnet import new_subnet
from fabriclib.ipam.common.vlan_refs import subnet_base, vlan_ref


def _free_name(plan, vlan):
    """Purpose: the name a VLAN's new subnet takes when none is given: the VLAN's own (`<location>-<VLAN name>` at
             another location, 1.10.4.46.1) while no subnet of the site has it, else `<that>-2`, `-3`, … (cut to fit
             one DNS label).
    Inputs:  plan — the site's plan; vlan — the VLAN's plan entry.
    Returns: str.
    Fails:   never.
    Feeds:   add_subnet."""
    used = {s["name"] for s in plan["subnets"]}
    base = subnet_base(vlan)
    if base not in used:
        return base
    n = 2
    while f"{base[:58]}-{n}" in used:
        n += 1
    return f"{base[:58]}-{n}"


def add_subnet(v, actor, vid, cidr, site="", name="", gateway="", dhcp=True, relay="", notes="", allow_overlap="",
               split=True, secrets=None, container="samba", source="cli",
               caller=None):
    """Purpose: another subnet given to a VLAN of a site's plan, or a first one to a VLAN kept as a record (manual
             1.10.4.16, 2.1.10.18: e.g. a second network while renumbering). Every rule still holds: the network
             overlaps no other in the organisation unless a reason is given, its gateway is one of its hosts, and in
             a /24 the suggested split is added unless asked not to (common/new_subnet).
    Inputs:  v — fabric vars (site_name, fabric_subnet); actor — who asks (audit); vid — the VLAN (`<id>`, or
             `<id>@<location>`); cidr — the network; site — whose plan ("" this site's); name — one DNS label ("" the
             VLAN's name, or
             `<VLAN name>-<n>` when a subnet has it); gateway — "" for the first host; dhcp — bool; relay — the relay's
             address when it lies outside the subnet; notes — text; allow_overlap — why it may overlap another
             network; split — bool; secrets, container, source, caller — as edit_plan.
    Returns: edit_plan's result; result = {"vlan", "subnet", "ranges"}.
    Fails:   ValidationError: no such VLAN; what check_subnet (an overlap, named; a name the site uses) or check_range
             refuses; what edit_plan refuses.
    Feeds:   ipam/cli/run_plan_change (subnet add), agent/post_networks."""
    def change(plan, read, org):
        vlan, _ = find_vlan(plan, vid)
        changes, sub, ranges = new_subnet(v, plan, org, vlan, str(cidr or "").strip(), name or _free_name(plan, vlan),
                                          gateway, dhcp, relay, notes, allow_overlap, split)
        out = {"vlan": vlan, "subnet": sub, "ranges": ranges}
        return changes, out, f"vlan={vlan_ref(vlan)} subnet={sub['cidr']} name={sub['name']}", []
    return edit_plan(v, actor, site, "IPAM_SUBNET_ADD", change, secrets, container, source, networks=True,
                     caller=caller)
