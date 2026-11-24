import ipaddress

from fabriclib.dns.split.split_answers import split_answers
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


def _inside(match, cidrs):
    """Purpose: a group's match-clients narrowed to a subnet with answers of its own (2.1.4.17): its negations
             kept as they are, each of its networks replaced by its overlap with the subnet's (the smaller of the
             two, when one holds the other; nothing, when they do not meet).
    Inputs:  match — a group's match-clients (_matches); cidrs — the subnet (a list of one).
    Returns: [address-match-list elements], or [] when the group has no client in the subnet.
    Fails:   never.
    Feeds:   resolver_views."""
    out, any_inside = [], False
    for elem in match:
        if elem.startswith("!"):
            out.append(elem)
            continue
        net = ipaddress.ip_network(elem, strict=False)
        for c in cidrs:
            sub = ipaddress.ip_network(c, strict=False)
            if net.subnet_of(sub):
                out.append(elem)
                any_inside = True
            elif sub.subnet_of(net):
                out.append(c)
                any_inside = True
    return list(dict.fromkeys(out)) if any_inside else []


def resolver_views(v, plan=None):
    """Purpose: what the resolver's views hold (manual 1.12.3.6): each group's match-clients (the most specific
             address wins), its rules zone and its safe search, and everyone's safe search. The lists are AdGuard
             Home's (1.12.3.5): no view holds one.
             A subnet with answers of its own (2.1.4.17) gets a view of its own, and a view per group with clients
             in it: those views come first (a group's clients in that subnet), then the groups', then the subnets',
             then everyone's, so the most specific still wins.
    Inputs:  v — checked vars (dns_filter_groups, dns_filter_safe_search, dns_filter_youtube, dns, domain); plan —
             the site's plan (default: the copy last read; split_answers).
    Returns: {"safe_zone": everyone's safe-search zone or None, "groups": [{name, match, rules_zone, safe_zone}],
             "splits": split_answers' subnets, "pairs": [{the group's fields, "name": "<group>-<view>", "match"
             (the group's clients in the subnet), "split" (the subnet's rpz)}], "subnets": [{"name" (its view),
             "match" ([the subnet]), "split" (its rpz)}]}.
    Fails:   never.
    Feeds:   dns_filter/deploy_resolver."""
    matches = _matches(v.get("dns_filter_groups") or [])
    groups = [{"name": g["name"], "match": matches[g["name"]], "rules_zone": f"group-{g['name']}.rpz",
               "safe_zone": SAFE_ZONES[g["youtube"]] if g["safe_search"] else None}
              for g in v.get("dns_filter_groups") or []]
    safe = SAFE_ZONES[v.get("dns_filter_youtube") or "strict"] if v.get("dns_filter_safe_search") else None
    splits = split_answers(v, plan)
    pairs = [{**g, "name": f"{g['name']}-{s['view']}", "group": g["name"], "match": _inside(g["match"], s["cidrs"]),
              "split": s["rpz"]} for s in splits for g in groups]
    return {"safe_zone": safe, "groups": groups, "splits": splits, "pairs": [p for p in pairs if p["match"]],
            "subnets": [{"name": s["view"], "match": s["cidrs"], "split": s["rpz"]} for s in splits]}
