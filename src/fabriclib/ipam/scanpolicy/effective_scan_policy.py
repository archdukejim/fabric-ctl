POLICIES = ("allow", "deny")


def _why(site, policy, source):
    """Purpose: what a denied scan says: which level denied it, and what could change it (manual 1.10.4.27.4).
    Inputs:  site — str; policy — "allow" or "deny"; source — effective_scan_policy's source.
    Returns: str ("" when scans are allowed).
    Fails:   never.
    Feeds:   effective_scan_policy."""
    if policy == "allow":
        return ""
    if source == "organisation (enforced)":
        return (f"scanning is denied at {site} by the organisation's scan policy (enforced): only the organisation's "
                "level can allow it (fabricctl ipam scan-policy set org allow, at the top site or a site it lets edit "
                "the organisation's settings)")
    if source.startswith("site "):
        return (f"scanning is denied at {site} by its own scan policy: fabricctl ipam scan-policy set site allow (or "
                f"inherit), at {site} or a site above it")
    return (f"scanning is denied at {site} by the organisation's scan policy: the site's own level may allow it "
            "(fabricctl ipam scan-policy set site allow)")


def effective_scan_policy(levels, site):
    """Purpose: whether scans may run at a site, and which level decides (decision 2.1.10.28, manual 1.10.4.27.3), as a
             group policy's enforcement works: the organisation's level when it is enforced (allow when it has no
             value); else the site's own value; else the organisation's; else allow. A value that is neither allow nor
             deny (not one fabric writes) counts as deny: the policy fails closed.
    Inputs:  levels — read_plan's "scan_policy" ({"org": {"policy", "enforced"}, <site>: {"policy"}}; {} or None
             when the domain holds none); site — the site asked about.
    Returns: {"site", "allowed" (bool), "policy" ("allow" or "deny"), "source" ("organisation (enforced)",
             "site <name>", "organisation" or "default"), "org": {"policy" ("" unset), "enforced" (bool)},
             "site_level": {"policy" ("" inherit)}, "why" (the refusal's text, "" when allowed)}.
    Fails:   never.
    Feeds:   read_scan_policy, networks_overview (the Networks tab's card), tests."""
    org = (levels or {}).get("org") or {}
    own = (levels or {}).get(site) or {}
    org_policy = str(org.get("policy") or "").lower()
    site_policy = str(own.get("policy") or "").lower()
    enforced = bool(org.get("enforced"))
    if enforced:
        policy, source = org_policy or "allow", "organisation (enforced)"
    elif site_policy:
        policy, source = site_policy, f"site {site}"
    elif org_policy:
        policy, source = org_policy, "organisation"
    else:
        policy, source = "allow", "default"
    if policy not in POLICIES:
        policy = "deny"
    return {"site": site, "allowed": policy == "allow", "policy": policy, "source": source,
            "org": {"policy": org_policy, "enforced": enforced}, "site_level": {"policy": site_policy},
            "why": _why(site, policy, source)}
