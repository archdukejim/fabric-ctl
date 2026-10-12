import os

from fabriclib.dns_filter.common.adguard_paths import adguard_paths
from fabriclib.dns_filter.common.list_id import list_id

# fabric's own rule, never the owner's to remove (1.12.3.2)
DS_PASS = "@@||*^$dnstype=DS,important"


def adguard_desired(v):
    """Purpose: what AdGuard Home should hold, from the vars (manual 1.12.3.4–1.12.3.6): the site's lists that have a
             local copy (ticked or not), fabric's DS rule and the owner's and each group's allows as its rules, the
             groups as its clients, the upstreams. The vars are the truth; AdGuard is made to match them
             (sync_adguard, deploy_adguard).
    Inputs:  v — checked vars (dns_filter_lists, dns_filter_allow, dns_filter_groups, dns_filter_upstreams,
             deploy_base_dir).
    Returns: {"filters": [{"id": int, "url": "/lists/<id>.txt", "name", "enabled": bool, "source": the list's URL}],
             "user_rules": [str], "groups": [names], "upstreams": ["tls://<address>", ...], "bootstrap": [addresses]}.
             A list with no copy yet is left out until the lists job has fetched it.
    Fails:   never.
    Feeds:   dns_filter/deploy_adguard (the rendered file), dns_filter/sync_adguard (the API)."""
    folder = adguard_paths(v)["lists"]
    filters = []
    for item in v.get("dns_filter_lists") or []:
        lid = list_id(item["url"])
        if os.path.exists(os.path.join(folder, f"{lid}.txt")):
            filters.append({"id": int(lid, 16), "url": f"/lists/{lid}.txt", "name": item.get("name") or item["url"],
                            "enabled": item.get("enabled", True) is not False, "source": item["url"]})
    # past every list, $important so a list's own important rule cannot win; the owner's blocks and a group's stay in
    # the resolver, ahead of AdGuard (1.12.3.2, 1.12.3.6)
    # first, every DS query passes: the resolver validates (2.1.12.7) and proves a blocked name's zone unsigned with it
    rules = [DS_PASS] + [f"@@||{n}^$important" for n in v.get("dns_filter_allow") or []]
    for g in v.get("dns_filter_groups") or []:
        rules += [f"@@||{n}^$client='{g['name']}',important" for n in g.get("allow") or []]
    ups = v.get("dns_filter_upstreams") or []
    return {"filters": filters, "user_rules": rules, "groups": [g["name"] for g in v.get("dns_filter_groups") or []],
            # DoT to each address, its certificate verified for that address: a provider's name may resolve to
            # addresses that serve no DoT (cloudflare-dns.com does: 2.3.1.18)
            "upstreams": list(dict.fromkeys(f"tls://{u['address']}" for u in ups)),
            "bootstrap": list(dict.fromkeys(str(u["address"]) for u in ups))}
