import copy
import ipaddress


def _remap(text, old, new):
    """Purpose: one address of the old subnet given the same host number in the new one.
    Inputs:  text — the address; old, new — IPv4Network.
    Returns: the new address (str); text unchanged when it is not in the old subnet; None when its host number does
             not fit the new subnet.
    Fails:   never (text that is not an address is returned unchanged).
    Feeds:   moved_plan."""
    try:
        ip = ipaddress.ip_address(str(text))
    except ValueError:
        return text
    if ip not in old:
        return text
    moved = new.network_address + (int(ip) - int(old.network_address))
    return str(moved) if moved in new and moved not in (new.network_address, new.broadcast_address) else None


def moved_plan(plan, old_cidr, new_cidr):
    """Purpose: a site's plan with the subnet of the host's old LAN moved to the new one (manual 1.3.7.7, the owner's
             choice 2026-11-19): its network, gateway, relay, ranges and addresses keep their host numbers (.200 stays
             .200), the rest of the plan as it is. Pure: used on the plan read while the move is pending, before and
             after move_lan_subnet writes it to the domain.
    Inputs:  plan — the site's plan (site_plan's); old_cidr, new_cidr — the LAN's old and new networks.
    Returns: (plan, [warning]): a copy, moved; the plan itself when no subnet is the old LAN's (nothing to move, or
             already moved); a warning for each range or address whose host number does not fit a smaller new subnet
             (left out).
    Fails:   ValueError for a network that is not one.
    Feeds:   ipam/load_address_plan (while restore-pending.json holds plan_move), ipam/move_lan_subnet."""
    old, new = ipaddress.ip_network(old_cidr, strict=False), ipaddress.ip_network(new_cidr, strict=False)
    at = next((i for i, s in enumerate(plan.get("subnets") or [])
               if ipaddress.ip_network(s["cidr"], strict=False) == old), None)
    if at is None:
        return plan, []
    out, warnings = copy.deepcopy(plan), []
    sub = out["subnets"][at]
    sub["cidr"] = str(new)
    for key in ("gateway", "relay"):
        if sub.get(key):
            sub[key] = _remap(sub[key], old, new) or ""
    ranges = []
    for r in sub.get("ranges") or []:
        first, last = _remap(r["first"], old, new), _remap(r["last"], old, new)
        if first and last:
            ranges.append(dict(r, first=first, last=last))
        else:
            warnings.append(f"address plan: range {r['first']} - {r['last']} does not fit {new}: left out")
    sub["ranges"] = ranges
    addresses = []
    for a in sub.get("addresses") or []:
        ip = _remap(a["ip"], old, new)
        if ip:
            addresses.append(dict(a, ip=ip))
        else:
            warnings.append(f"address plan: {a['ip']} ({a.get('name') or a.get('kind')}) does not fit {new}: left out")
    sub["addresses"] = addresses
    return out, warnings
