def local_scan_state(levels, site):
    """Purpose: whether a site's own admins may start scans there, and who decided (decision 2.1.10.30, manual
             1.10.4.29.4): the top site always may (no site is above it); any other site only when a site above set it
             allowed; unset, off. A scan triggered from above does not ask this.
    Inputs:  levels — read_plan's "local_scan" ({site: {"allowed", "set_by", "top"}}; {} or None from a DC or a kept
             copy without it); site — the site asked about.
    Returns: {"site", "top" (bool), "allowed" (bool), "set_by" (who set it, "" when unset), "source" ("the top site",
             "set from above", "default (off)"), "why" (the refusal's text, "" when allowed)}.
    Fails:   never.
    Feeds:   read_local_scan, networks_overview (the Networks tab's card), tests."""
    own = (levels or {}).get(site) or {}
    top = bool(own.get("top"))
    set_by = str(own.get("set_by") or "")
    if top:
        allowed, source = True, "the top site"
    else:
        allowed = own.get("allowed") is True
        source = "set from above" if set_by else "default (off)"
    why = "" if allowed else (
        f"local scans at {site} are off: the sites above it decide ("
        + (f"set by {set_by}" if set_by else "not set: off by default")
        + f"); a site above may scan here: Scan at {site} on its Networks tab, or fabricctl ipam scan <subnet> "
        f"--site {site}")
    return {"site": site, "top": top, "allowed": allowed, "set_by": set_by, "source": source, "why": why}
