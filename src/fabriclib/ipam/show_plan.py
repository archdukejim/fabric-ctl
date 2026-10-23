from fabriclib.ipam.common.site_plan import site_plan
from fabriclib.ipam.plan_rows import plan_rows
from fabriclib.ipam.suggestions import suggest_block


def show_plan(read, site, leases=None):
    """Purpose: `fabricctl ipam show` (manual 1.10.4.16): one site's plan as text: its number (or the one fabric
             suggests), each VLAN with each of its subnets (2.1.10.18), their ranges and address table, and the
             site's other networks.
    Inputs:  read — read_plan's result; site — str; leases — this site's leases (list_leases) or None.
    Returns: str, lines ending in a newline.
    Fails:   never for a plan fabric wrote.
    Feeds:   ipam/cli/run_plan_read (show)."""
    plan = site_plan(read, site)
    block = plan["block"]
    lines = [f"site {site}  number " + (str(block) if block else
                                        f"none (suggested {suggest_block(read['sites'], site)})")]
    rows = plan_rows(plan, leases)
    for v in plan["vlans"]:
        subs = [s for s in plan["subnets"] if s.get("vlan") == v["id"]]
        head = f"VLAN {v['id']:<5} {v['name']:<16} "
        if not subs:
            lines.append(head + "(no subnet)" + (f"  {v['purpose']}" if v["purpose"] else ""))
            continue
        for i, sub in enumerate(subs):
            lead = head if i == 0 else " " * len(head)
            served = "on" if sub["dhcp"] else "off"
            lines.append(lead + f"{sub['cidr']:<18} gateway {sub['gateway'] or '-'}  DHCP {served}"
                         + (f"  access {v['access']}" if i == 0 else "")
                         + (f"  subnet {sub['name']}" if sub["name"] != v["name"] else "")
                         + (f"  relay {sub['relay']}" if sub["relay"] else "")
                         + (f"  {v['purpose']}" if v["purpose"] and i == 0 else ""))
            if sub["ranges"]:
                lines.append("  ranges: " + ", ".join(f"{r['kind']} {r['first']}-{r['last']}" for r in sub["ranges"]))
            for r in rows:
                if r["subnet"] == sub["cidr"]:
                    lines.append(f"  {r['ip']:<15} {r['kind']:<14} {r['name']:<16} {r['mac']:<17} {r['owner']}"
                                 + ("  dns" if r["dns"] else "") + (f"  lease {r['lease']}" if r["lease"] else ""))
    for n in plan["networks"]:
        lines.append(f"network {n['name']}  {n['cidr']}  ({n['kind']})")
    return "\n".join(lines) + "\n"
