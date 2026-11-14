from fabriclib.ipam.rules.access_table import access_table
from fabriclib.ipam.rules.access_warnings import access_warnings
from fabriclib.ipam.rules.constants import ANY, FABRIC, GUARDED, SERVICES
from fabriclib.ipam.rules.rule_networks import rule_networks


def access_view(v, plan, own):
    """Purpose: what the console's Access page shows of a site (manual 1.10.4.48.11, decision 2.1.10.63): a tab per
             VLAN (the host's first), then Other sites and Outside, each with the eight services, their ports and
             whether each is allowed; the warnings.
    Inputs:  v — fabric vars (host_ip, lan_cidr: this site's host); plan — the site's plan (site_plan's); own —
             whether it is this install's site (another site's host address is not known here).
    Returns: {"networks": [{"key", "label", "cidrs" (str), "host" (bool), "services": [{"name", "ports", "allow"
             (bool), "guarded" (bool: the host's SSH and console)}]}], "kept" (bool), "warnings": [str],
             "host_lan" (the host's network when no VLAN holds it, else "")}.
    Fails:   never.
    Feeds:   ipam/networks_overview."""
    nets = rule_networks(v if own else {}, plan)
    table = access_table(plan, nets["host_vlan"])
    host = nets["host_vlan"]
    order = ([host] if host else []) + [r for r in nets["vlans"] if r != host] + [FABRIC, ANY]
    labels = {FABRIC: "Other sites", ANY: "Outside"}
    cidrs = {FABRIC: f"every network of the domain's other sites ({len(nets['fabric']) - len(nets['site'])})",
             ANY: "every other address, outside ones too"}
    networks = [{"key": k, "label": labels.get(k, f"VLAN {k}"), "host": k == host,
                 "cidrs": cidrs.get(k) or ", ".join(nets["vlans"].get(k) or []) or "no subnet yet",
                 "services": [{"name": s, "ports": p, "allow": table[k][s] == "allow",
                               "guarded": k == host and s in GUARDED} for s, p in SERVICES.items()]}
                for k in order]
    return {"networks": networks, "kept": bool(plan.get("rules_kept")), "warnings": access_warnings(table, nets),
            "host_lan": "" if host else ", ".join(nets["host"])}
