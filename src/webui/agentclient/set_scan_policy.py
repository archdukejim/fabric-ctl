from webui.agentclient.connection import call_agent


def set_scan_policy(level, site, policy, enforced=""):
    """Purpose: Set one level of the scan policy (manual 1.10.4.27.5): a site's (POST /v1/ipam/scan-policy, dhcp:write)
             or the organisation's (POST /v1/ipam/scan-policy/org, dhcp:org-options). Timeout 120 s.
    Inputs:  level — "org" or "site"; site — the site (a site's level); policy — "allow", "deny" or (a site's)
             "inherit"; enforced — "on", "off" or "" to keep it (the organisation's). Checked by fabriclib.
    Returns: fabriclib.ipam.scanpolicy.set_scan_policy's result ({"result": {"level", "site", "policy", "enforced"},
             ...}).
    Fails:   the call_agent exceptions: AgentError, ValidationError (400: a value refused, a site this console does not
             show, the directory refusing), AuthError (401), PermissionDenied (403: no dhcp:write or dhcp:org-options).
    Feeds:   src/webui/routes/networks_scan_post."""
    if level == "org":
        return call_agent("POST", "/v1/ipam/scan-policy/org", {"policy": policy, "enforced": enforced}, timeout=120)
    return call_agent("POST", "/v1/ipam/scan-policy", {"site": site, "policy": policy}, timeout=120)
