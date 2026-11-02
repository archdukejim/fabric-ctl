from webui.agentclient.connection import call_agent


def request_scan(site, subnet):
    """Purpose: Ask another site to scan one of its subnets, done at once (manual 1.10.4.40.2, 1.10.4.36): a request
             written into the domain, which that site's plan poll runs and answers. Agent route: POST
             /v1/ipam/scan/request (dhcp:write), timeout 120 s.
    Inputs:  site — the site; subnet — its name or network. Checked by fabriclib.
    Returns: request_scan's result: {"id", "site", "subnet", "cidr", "state", "requested_by", "actor"}.
    Fails:   the call_agent exceptions: AgentError, ValidationError (400: no grant gives the person networks scan at
             the site, a subnet not in its plan, one already pending, the directory refusing), AuthError (401),
             PermissionDenied (403: no dhcp:write).
    Feeds:   src/webui/routes/networks_scan_post."""
    return call_agent("POST", "/v1/ipam/scan/request", {"site": site, "subnet": subnet}, timeout=120)
