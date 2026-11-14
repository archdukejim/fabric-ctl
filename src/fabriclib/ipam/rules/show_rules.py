from fabriclib.ipam.rules.constants import ANY, HOST, SERVICES


def _source(word, nets):
    """Purpose: a rule's source as shown, with the networks it stands for.
    Inputs:  word — the rule's "from"; nets — rule_networks' result.
    Returns: str, e.g. "host (10.1.10.0/24)", "20 (10.1.20.0/24)", "any".
    Fails:   never.
    Feeds:   show_rules."""
    cidrs = nets["host"] if word == HOST else [] if word == ANY else nets["vlans"].get(word, [])
    return f"{word} ({', '.join(cidrs)})" if cidrs else word


def show_rules(rules, nets, kept=True):
    """Purpose: a site's access rules as `fabricctl ipam rule` prints them (manual 1.10.4.48.5): numbered, each with
             its source's networks and its service's ports, the implied deny last.
    Inputs:  rules — the site's rules, in order; nets — rule_networks' result; kept — whether they are kept on the
             site's record (False: the rules it has until some are written, said).
    Returns: list of str.
    Fails:   never.
    Feeds:   ipam/cli/run_plan_read (`ipam rule`)."""
    rows = [(str(n), "from " + _source(r["from"], nets), r["service"], r["action"],
             "all of them" if r["service"] == ANY else SERVICES[r["service"]]) for n, r in enumerate(rules, 1)]
    rows.append(("*", "from any", ANY, "deny", "implied: nothing else is answered"))
    widths = [max(len(row[i]) for row in rows) for i in range(4)]
    lines = ["  ".join(cell.ljust(widths[i]) if i < 4 else cell for i, cell in enumerate(row)).rstrip()
             for row in rows]
    if not kept:
        lines.append("(none written yet: these are the rules the site has until one is changed)")
    return lines
