from fabriclib.ipam.rules.constants import ANY, FABRIC, SERVICES


def show_access(table, nets, kept=True):
    """Purpose: a site's access table as `fabricctl ipam access` prints it (manual 1.10.4.48.11): one line per
             network with its networks, then each service allowed or not.
    Inputs:  table — access_table's shape; nets — rule_networks' result; kept — whether rows are kept on the site's
             record (False: the table it has until one is written, said).
    Returns: list of str.
    Fails:   never.
    Feeds:   ipam/cli/run_plan_read (`ipam access`)."""
    lines = ["  ".join(["network".ljust(14), *[s.ljust(6) for s in SERVICES]]).rstrip()]
    for net, row in table.items():
        if net == FABRIC:
            label = "fabric"
        elif net == ANY:
            label = "any"
        else:
            label = net + (" (host)" if net == nets["host_vlan"] else "")
        lines.append("  ".join([label.ljust(14), *[("yes" if row[s] == "allow" else "-").ljust(6)
                                                   for s in SERVICES]]).rstrip())
    for ref, cidrs in nets["vlans"].items():
        if cidrs:
            lines.append(f"VLAN {ref}: {', '.join(cidrs)}")
    if not nets["host_vlan"] and nets["host"]:
        lines.append(f"the host's network ({', '.join(nets['host'])}) is in no VLAN of the plan: it reaches everything")
    if not kept:
        lines.append("(none written yet: this is what the site has until one is changed)")
    return lines
