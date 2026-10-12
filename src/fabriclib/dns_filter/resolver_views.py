import ipaddress

from fabriclib.dns_filter.common.safe_search import ZONES as SAFE_ZONES


def _matches(groups):
    """Purpose: each group's match-clients, so that the most specific address wins and no two groups match one
             client: before each of a group's entries, the other groups' more specific entries inside it, negated.
    Inputs:  groups — the checked groups (check_filter_groups: clients normalised, never the same entry twice).
    Returns: {group name: [address-match-list elements, in order]}.
    Fails:   never.
    Feeds:   resolver_views."""
    entries = [(g["name"], ipaddress.ip_network(c)) for g in groups for c in g["clients"]]
    out = {}
    for g in groups:
        elems = []
        for c in g["clients"]:
            net = ipaddress.ip_network(c)
            inner = sorted((n for owner, n in entries if owner != g["name"] and n != net and n.subnet_of(net)),
                           key=lambda n: (-n.prefixlen, int(n.network_address)))
            elems += ["!" + (str(n.network_address) if n.prefixlen == 32 else str(n)) for n in inner]
            elems.append(c)
        out[g["name"]] = list(dict.fromkeys(elems))
    return out


def resolver_views(v):
    """Purpose: what the resolver's views hold (manual 1.12.3.6): each group's match-clients (the most specific
             address wins), its rules zone and its safe search, and everyone's safe search. The lists are AdGuard
             Home's (1.12.3.5): no view holds one.
    Inputs:  v — checked vars (dns_filter_groups, dns_filter_safe_search, dns_filter_youtube).
    Returns: {"safe_zone": everyone's safe-search zone or None, "groups": [{name, match, rules_zone, safe_zone}]}.
    Fails:   never.
    Feeds:   dns_filter/deploy_resolver."""
    matches = _matches(v.get("dns_filter_groups") or [])
    groups = [{"name": g["name"], "match": matches[g["name"]], "rules_zone": f"group-{g['name']}.rpz",
               "safe_zone": SAFE_ZONES[g["youtube"]] if g["safe_search"] else None}
              for g in v.get("dns_filter_groups") or []]
    safe = SAFE_ZONES[v.get("dns_filter_youtube") or "strict"] if v.get("dns_filter_safe_search") else None
    return {"safe_zone": safe, "groups": groups}
