from webui.agentclient.connection import call_agent


def request_scan(site, subnet):
    """Purpose: Ask a site below this one to scan one of its subnets (manual 1.10.4.29.3): a request written into AD,
             which that site's plan poll runs and answers. Agent route: POST /v1/ipam/scan/request (dhcp:write),
             timeout 120 s.
    Inputs:  site — the site below; subnet — its name or network. Checked by fabriclib.
    Returns: fabriclib.ipam.scancontrol.request_scan's result: {"id", "site", "subnet", "cidr", "state", "requested_by",
             "actor"}.
    Fails:   the call_agent exceptions: AgentError, ValidationError (400: a site not below this one, a subnet not in its
             plan, one already pending, the directory refusing), AuthError (401), PermissionDenied (403: no
             dhcp:write).
    Feeds:   src/webui/routes/networks_scan_post."""
    return call_agent("POST", "/v1/ipam/scan/request", {"site": site, "subnet": subnet}, timeout=120)
