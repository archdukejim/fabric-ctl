from webui.agentclient.connection import call_agent


def set_local_scan(site, allowed):
    """Purpose: Set whether a site below this one may scan locally (manual 1.10.4.29.4). Agent route: POST
             /v1/ipam/local-scan (dhcp:write), timeout 120 s.
    Inputs:  site — the site below; allowed — "on", "off" or "clear". Checked by fabriclib.
    Returns: fabriclib.ipam.scancontrol.set_local_scan's result ({"result": {"site", "allowed", "set_by"}, ...}).
    Fails:   the call_agent exceptions: AgentError, ValidationError (400: this site, a site not below it, a value
             that is neither, the directory refusing), AuthError (401), PermissionDenied (403: no dhcp:write).
    Feeds:   src/webui/routes/networks_scan_post."""
    return call_agent("POST", "/v1/ipam/local-scan", {"site": site, "allowed": allowed}, timeout=120)
