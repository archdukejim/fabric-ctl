from fabriclib.dns.reverse_zones import reverse_zones


def filter_zones(v, links):
    """Purpose: fabric's own zones, which the DNS filter forwards to this site's BIND and never filters: this site's
             domain, the organisation's, the other forward zones in `dns:` (added in the console or the menu, manual
             1.4.1.3), the linked sites' (secondary zones on this BIND, M4), the reverse zones and the AD zone (which
             may sit beside fabric's domain, e.g. ad.<parent>).
    Inputs:  v — fabric vars (domain, org_domain, dns, ad_domain and what reverse_zones reads); links —
             dns_links' result.
    Returns: list of zone names without duplicates, this site's domain first.
    Fails:   errors from reverse_zones on malformed records.
    Feeds:   dns_filter/deploy_resolver; tests/samba/run.py, tests/zones/run.py."""
    names = [v["domain"], v.get("org_domain") or v["domain"]]
    names += [key for key in v.get("dns") or {} if key != "dynamic_zone_var"]       # its other zones (1.4.1.3)
    names += [link["domain"] for link in (links or {}).get("children") or []]
    if (links or {}).get("upstream"):
        names.append(links["upstream"]["domain"])
    names += list(reverse_zones(v)["zones"])
    # the Windows domain's zone (BIND serves it through DLZ): needed when it is not under fabric's domain (2.1.6.11)
    names.append(v.get("ad_domain"))
    return list(dict.fromkeys(n for n in names if n))
