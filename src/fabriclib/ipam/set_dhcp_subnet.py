from fabriclib.common.errors import ValidationError
from fabriclib.ipam.check_range import check_range
from fabriclib.ipam.common.change_subnet import change_subnet
from fabriclib.ipam.common.edit_plan import edit_plan
from fabriclib.ipam.common.fields import KEEP, find_subnet, ipv4
from fabriclib.ipam.common.pool_text import pool_text


def set_dhcp_subnet(v, actor, which, router=KEEP, notes=KEEP, allow_overlap=KEEP, add_pools=(), remove_pools=(),
                    secrets=None, container="samba", source="cli"):
    """Purpose: 0.7's `fabricctl dhcp set-subnet` once the subnets live in the plan: an alias of `fabricctl ipam subnet
             set` and `range add|remove` (manual 1.10.4.9, 1.10.4.21, decision 2.1.10.27), made as one change: the
             router (the gateway), notes and overlap reason under the rules of `subnet set` (common/change_subnet),
             each pool removed (a dhcp range starting at its first address) and each pool added (a dhcp range,
             check_range). A refusal writes nothing. A subnet's name and VLAN stay in the plan (the alias refuses
             --name and --vlan before calling this).
    Inputs:  v — fabric vars; actor — who asks (audit); which — the subnet's name or network; router ("" none),
             notes, allow_overlap ("" none) — new values, KEEP leaves one; add_pools, remove_pools — lists of
             "first - last"; secrets, container, source — as edit_plan.
    Returns: edit_plan's result; result = the subnet as it will be, with "ranges".
    Fails:   ValidationError: nothing to change; no such subnet; a pool to remove that is not one of its dhcp ranges;
             what change_subnet, check_range or edit_plan refuses.
    Feeds:   dhcp/run_dhcp_alias (set-subnet)."""
    given = {k: x for k, x in (("gateway", router), ("notes", notes), ("allow_overlap", allow_overlap))
             if x is not KEEP}
    if not given and not add_pools and not remove_pools:
        raise ValidationError("nothing to change: give --router, --notes, --allow-overlap, --add-pool or "
                              "--remove-pool")

    def change(plan, read, org):
        sub = find_subnet(plan, which)
        changes, new = [], dict(sub)
        ranges = list(sub.get("ranges") or [])
        for p in remove_pools:
            first, last = pool_text(p)
            first, last = str(ipv4(first, "pool")), str(ipv4(last, "pool"))
            rng = next((r for r in ranges if r["kind"] == "dhcp" and r["first"] == first), None)
            if rng is None or rng["last"] != last:
                raise ValidationError(f"subnet {sub['name']} has no DHCP pool {first} - {last}")
            ranges.remove(rng)
            changes.append({"do": "remove", "what": "range", "site": plan["site"], "subnet": sub["name"],
                            "key": f"dhcp-{first}"})
        if given:
            sub_change, new = change_subnet(v, plan, org, {**sub, "ranges": ranges}, given)
            changes.append(sub_change)
        held = {**new, "ranges": ranges, "addresses": sub.get("addresses") or []}
        for p in add_pools:
            first, last = pool_text(p)
            rng = check_range({"kind": "dhcp", "first": first, "last": last, "notes": ""}, held)
            held["ranges"] = held["ranges"] + [rng]
            changes.append({"do": "add", "what": "range", "site": plan["site"], "subnet": sub["name"],
                            "key": f"dhcp-{rng['first']}", "fields": rng})
        detail = " ".join(f"{k}={x}" for k, x in given.items())
        return changes, {**new, "ranges": held["ranges"]}, (
            f"alias=dhcp set-subnet subnet={sub['name']} {detail} add_pools={list(add_pools)} "
            f"remove_pools={list(remove_pools)}"), []
    return edit_plan(v, actor, "", "IPAM_SUBNET_SET", change, secrets, container, source, networks=bool(given))
