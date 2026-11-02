from fabriclib.ipam.check_range import check_range
from fabriclib.ipam.check_vlan import check_vlan
from fabriclib.ipam.common.edit_plan import edit_plan
from fabriclib.ipam.common.new_subnet import new_subnet
from fabriclib.ipam.common.pool_text import pool_text


def add_dhcp_subnet(v, actor, network, name, vlan=None, router=None, pools=(), notes="", allow_overlap="",
                    secrets=None, container="samba", source="cli", caller=None):
    """Purpose: 0.7's `fabricctl dhcp add-subnet` once the subnets live in the plan: an alias of `fabricctl ipam`
             (manual 1.10.4.9, 1.10.4.21, decision 2.1.10.27), made as one change to the site's plan: the VLAN when
             the plan has none of that ID (named after the subnet; without --vlan the lowest free ID, as the upgrade
             chooses, 1.10.4.15), the subnet served by DHCP under every rule of `ipam subnet add` (common/new_subnet),
             its router as the gateway, and each pool a dhcp range; with no pool, a /24's suggested split. A refusal
             writes nothing.
    Inputs:  v — fabric vars; actor — who asks (audit); network — the subnet; name — its name (one DNS label);
             vlan — int or None; router — its gateway or None (the first host); pools — list of "first - last";
             notes, allow_overlap — str; secrets, container, source, caller — as edit_plan.
    Returns: edit_plan's result; result = {"vlan", "vlan_added" (bool), "subnet", "ranges"}.
    Fails:   ValidationError: what check_vlan, check_subnet (an overlap, named), check_range or edit_plan refuses; a
             pool that is not two addresses.
    Feeds:   dhcp/run_dhcp_alias (add-subnet)."""
    def change(plan, read, org):
        changes, added = [], False
        own = [x for x in plan["vlans"] if not x.get("location")]     # 0.7's commands: the DC's own location
        vid = vlan if vlan is not None else next(n for n in range(1, 4095) if n not in {x["id"] for x in own})
        rec = next((x for x in own if x["id"] == vid), None)
        if rec is None:
            rec = check_vlan({"id": vid, "name": name, "access": "full", "purpose": "", "notes": ""}, plan)
            changes.append({"do": "add", "what": "vlan", "site": plan["site"], "key": str(rec["id"]), "fields": rec})
            plan = {**plan, "vlans": plan["vlans"] + [rec]}
            added = True
        more, sub, ranges = new_subnet(v, plan, org, rec, str(network or "").strip(), name, router or "", True, "",
                                       notes, allow_overlap, split=not pools)
        changes += more
        held = {**sub, "ranges": list(ranges), "addresses": []}
        for p in pools:
            first, last = pool_text(p)
            rng = check_range({"kind": "dhcp", "first": first, "last": last, "notes": ""}, held)
            held["ranges"].append(rng)
            changes.append({"do": "add", "what": "range", "site": plan["site"], "subnet": sub["name"],
                            "key": f"dhcp-{rng['first']}", "fields": rng})
        out = {"vlan": rec, "vlan_added": added, "subnet": sub, "ranges": held["ranges"]}
        return changes, out, f"alias=dhcp add-subnet vlan={rec['id']} subnet={sub['cidr']} name={sub['name']}", []
    return edit_plan(v, actor, "", "IPAM_SUBNET_ADD", change, secrets, container, source, networks=True,
                     caller=caller)
