from fabriclib.ipam.common.vlan_refs import vlan_ref
from fabriclib.ipam.rules.constants import ANY, HOST, SERVICES
from fabriclib.ipam.rules.effective_rules import effective_rules
from fabriclib.ipam.rules.rule_networks import rule_networks
from fabriclib.ipam.rules.rule_warnings import rule_warnings


def rules_view(v, plan, own):
    """Purpose: what the console's Access rules card shows of a site (manual 1.10.4.48.5): each rule with the networks
             its source stands for and its service's ports, the implied deny, the warnings, and the choices its Add
             form offers.
    Inputs:  v — fabric vars (host_ip, lan_cidr: this site's host); plan — the site's plan (site_plan's); own —
             whether it is this install's site (another site's host address is not known here).
    Returns: {"rules": [{"n", "from", "networks" (str), "service", "ports", "action"}], "kept" (bool), "warnings":
             [str], "sources": [str] (host, any, then each VLAN), "services": [{"name", "ports"}] (any last)}.
    Fails:   never.
    Feeds:   ipam/networks_overview."""
    rules = effective_rules(plan)
    nets = rule_networks(v if own else {}, plan)

    def networks(word):
        cidrs = nets["host"] if word == HOST else [] if word == ANY else nets["vlans"].get(word, [])
        return ", ".join(cidrs) or ("every network the site knows" if word == ANY else "")
    rows = [{"n": n, "from": r["from"], "networks": networks(r["from"]), "service": r["service"],
             "ports": "all of them" if r["service"] == ANY else SERVICES[r["service"]], "action": r["action"]}
            for n, r in enumerate(rules, 1)]
    return {"rules": rows, "kept": bool(plan.get("rules_kept")), "warnings": rule_warnings(rules, nets),
            "sources": [HOST, ANY, *[vlan_ref(x) for x in plan.get("vlans") or []]],
            "services": [{"name": s, "ports": p} for s, p in SERVICES.items()] + [{"name": ANY, "ports": "all"}]}
