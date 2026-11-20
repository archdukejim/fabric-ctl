import ipaddress

from fabriclib.backup.restore_pending import read_restore_pending, write_restore_pending
from fabriclib.ipam.add_address import add_address
from fabriclib.ipam.add_range import add_range
from fabriclib.ipam.add_subnet import add_subnet
from fabriclib.ipam.common.site_plan import site_plan
from fabriclib.ipam.moved_plan import moved_plan
from fabriclib.ipam.read_plan import read_plan
from fabriclib.ipam.remove_subnet import remove_subnet

ACTOR = "restore"


def _vid(sub):
    """Purpose: how the plan's functions name a subnet's VLAN.
    Inputs:  sub — a subnet of the plan.
    Returns: "<id>" or "<id>@<location>".
    Fails:   never.
    Feeds:   move_lan_subnet."""
    return f"{sub['vlan']}@{sub['location']}" if sub.get("location") else str(sub["vlan"])


def move_lan_subnet(v, config_dir, secrets, container="samba"):
    """Purpose: after a restore to another subnet (manual 1.3.7.7), once the DC runs: the plan's subnet of the old LAN
             moved to the new one in the domain, as `fabricctl ipam` would (the old one removed with its ranges and
             addresses, the new one added to the same VLAN under the same name, then each range and address with its
             host number kept: moved_plan), then crossed off restore-pending.json. Resumable: what is pending keeps
             the old subnet as it was, and a run that stopped part way adds only what is missing.
    Inputs:  v — fabric vars (site_name, dc_name); config_dir — fabric's config folder (restore-pending.json's
             plan_move: {"from", "to", "subnet"}); secrets — fabric's secrets; container — the DC's container.
    Returns: list of str, what was done ([] when nothing is pending).
    Fails:   ValidationError from the plan's functions (a rule refused, the DC not answering): the move stays pending
             and the next setup or apply goes on with it.
    Feeds:   setup/start_services (after the domain converges)."""
    pending = read_restore_pending(config_dir)
    move = pending.get("plan_move")
    if not move:
        return []
    old, new = ipaddress.ip_network(move["from"], strict=False), ipaddress.ip_network(move["to"], strict=False)
    plan = site_plan(read_plan(v, secrets, of=v["site_name"], container=container), v["site_name"])
    by_cidr = {ipaddress.ip_network(s["cidr"], strict=False): s for s in plan.get("subnets") or []}
    lines = []
    if old in by_cidr:                             # keep it whole in the pending record first, then remove it
        move["subnet"] = by_cidr[old]
        write_restore_pending(config_dir, dict(pending, plan_move=move))
        remove_subnet(v, ACTOR, str(old), force=True, secrets=secrets, container=container, source="setup")
        lines.append(f"address plan: {old} removed (its VLAN keeps its name and moves to {new})")
    if not move.get("subnet"):                     # no subnet held the old LAN: nothing to move
        pending.pop("plan_move")
        write_restore_pending(config_dir, pending)
        return lines
    moved, warnings = moved_plan({"subnets": [move["subnet"]]}, str(old), str(new))
    target, have = moved["subnets"][0], by_cidr.get(new)
    if have is None:
        add_subnet(v, ACTOR, _vid(target), str(new), name=target["name"], gateway=target.get("gateway") or "",
                   dhcp=bool(target.get("dhcp")), relay=target.get("relay") or "", notes=target.get("notes") or "",
                   allow_overlap=target.get("allow_overlap") or "", split=False, secrets=secrets,
                   container=container, source="setup")
        lines.append(f"address plan: {new} added to VLAN {_vid(target)} as {target['name']}")
        have = {"ranges": [], "addresses": []}
    firsts = {r["first"] for r in have.get("ranges") or []}
    for r in target.get("ranges") or []:
        if r["first"] not in firsts:
            add_range(v, ACTOR, _vid(target), r["kind"], r["first"], r["last"], notes=r.get("notes") or "",
                      secrets=secrets, container=container, source="setup")
            lines.append(f"address plan: {r['kind']} range {r['first']} - {r['last']}")
    ips = {a["ip"] for a in have.get("addresses") or []}
    for a in target.get("addresses") or []:
        if a["ip"] not in ips:
            add_address(v, ACTOR, a["ip"], a["kind"], name=a.get("name") or "", mac=a.get("mac") or "",
                        owner=a.get("owner") or "", notes=a.get("notes") or "", dns=bool(a.get("dns")),
                        vid=_vid(target), secrets=secrets, container=container, source="setup")
            lines.append(f"address plan: {a['ip']} {a.get('name') or a['kind']}")
    if target.get("options") or any(a.get("options") for a in target.get("addresses") or []):
        lines.append(f"address plan: {new}'s DHCP options were not carried over: set them again (manual 4.10.1)")
    pending = read_restore_pending(config_dir)
    pending.pop("plan_move", None)
    write_restore_pending(config_dir, pending)
    return lines + warnings

