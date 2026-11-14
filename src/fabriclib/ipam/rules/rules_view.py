from fabriclib.ipam.common.vlan_refs import vlan_ref
from fabriclib.ipam.rules.constants import ANY, FABRIC, HOST, SERVICES, SITE
from fabriclib.ipam.rules.effective_rules import effective_rules
from fabriclib.ipam.rules.rule_networks import rule_networks
from fabriclib.ipam.rules.rule_warnings import rule_warnings
from fabriclib.ipam.rules.source_networks import source_networks


def rules_view(v, plan, own):
    """Purpose: what the console's Access rules page shows of a site (manual 1.10.4.48.5): each rule with the
             networks its source stands for and its service's ports, the implied deny, the warnings, and the
             choices of its rows (decision 2.1.10.62: site first, the new row's default).
    Inputs:  v — fabric vars (host_ip, lan_cidr: this site's host); plan — the site's plan (site_plan's); own —
             whether it is this install's site (another site's host address is not known here).
    Returns: {"rules": [{"n", "from", "networks" (str), "service", "ports", "action"}], "kept" (bool), "warnings":
             [str], "sources": [{"value", "label"}] (site, host, fabric, any, each VLAN, each subnet), "services":
             [{"name", "ports"}] (any last)}.
    Fails:   never.
    Feeds:   ipam/networks_overview."""
    rules = effective_rules(plan)
    nets = rule_networks(v if own else {}, plan)
    rows = [{"n": n, "from": r["from"], "networks": source_networks(r["from"], nets), "service": r["service"],
             "ports": "all of them" if r["service"] == ANY else SERVICES[r["service"]], "action": r["action"]}
            for n, r in enumerate(rules, 1)]
    words = [(SITE, "site (every network here)"), (HOST, "host (the host's VLAN)"),
             (FABRIC, "fabric (every site)"), (ANY, "any (every address)")]
    sources = [{"value": w, "label": label} for w, label in words]
    sources += [{"value": vlan_ref(x), "label": f"VLAN {vlan_ref(x)}"} for x in plan.get("vlans") or []]
    sources += [{"value": c, "label": c} for c in nets["subnets"]]
    return {"rules": rows, "kept": bool(plan.get("rules_kept")), "warnings": rule_warnings(rules, nets),
            "sources": sources,
            "services": [{"name": s, "ports": p} for s, p in SERVICES.items()] + [{"name": ANY, "ports": "all"}]}
