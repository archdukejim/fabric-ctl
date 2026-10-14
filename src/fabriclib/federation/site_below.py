def site_below(sites, me, target):
    """Purpose: whether a site sits below this one in the domain: its OU inside this site's OU (1.9.8.14) — the rule
             for what a site above may ask of a site (decisions 2.1.9.23, 2.1.6.58).
    Inputs:  sites — domain_sites()'s list [{"site", "dn"}]; me, target — site names.
    Returns: (bool, str): whether, and where the target sits ("" when it is not in the domain).
    Fails:   never.
    Feeds:   federation/request_dc_type, federation/rodc_lost."""
    dns = {s["site"]: str(s.get("dn") or "") for s in sites}
    mine, theirs = dns.get(me, ""), dns.get(target, "")
    return bool(mine and theirs and theirs.lower().endswith("," + mine.lower())), theirs
