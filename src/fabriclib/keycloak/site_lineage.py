def site_lineage(v):
    """Purpose: this site and the sites above it, read from where its OU sits (2.1.6.20: a site's OU is in its
             parent's), for the console roles a site above grants, which reach every site below it (2.1.9.21, revised
             2026-10-13).
    Inputs:  v — fabric vars (ad_site_ou, e.g. "OU=branch1,OU=region1,OU=hq,OU=sites"; site_name).
    Returns: (list of str, this site first then each site above it, nearest first — lower-cased; str, the top site's OU
             relative to the domain, e.g. "OU=hq,OU=sites").
    Fails:   ValueError for an ad_site_ou that is not a chain of OU= parts ending in OU=sites, or whose first part is
             not this site.
    Feeds:   ensure_site_group_mapper, configure_keycloak (site_bundle_grants)."""
    parts = [p.strip() for p in str(v["ad_site_ou"]).split(",") if p.strip()]
    if len(parts) < 2 or parts[-1].lower() != "ou=sites" or not all(p[:3].lower() == "ou=" for p in parts):
        raise ValueError(f"ad_site_ou {v['ad_site_ou']!r} is not a site's OU under OU=sites")
    names = [p[3:].lower() for p in parts[:-1]]
    if names[0] != str(v["site_name"]).lower():
        raise ValueError(f"ad_site_ou {v['ad_site_ou']!r} is not site {v['site_name']}'s OU")
    return names, ",".join(parts[-2:])
