from webui.agentclient.connection import call_agent


def scannable_subnets():
    """Purpose: What the scan page shows before a scan (manual 1.10.4.40.1, 1.10.4.36): the subnets of this site's plan
             a scan may cover, and whether the signed-in person may scan here (the grant's networks scan right).
             Agent route: GET /v1/ipam/scan (dhcp:read).
    Inputs:  none.
    Returns: {"site", "subnets": [{"name", "cidr", "vlan", "dhcp", "hosts"}], "may" (bool), "why" ("" or why not)}.
    Fails:   the call_agent exceptions: AgentError, ValidationError (400), AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/networks_scan_page, networks_scan_post."""
    return call_agent("GET", "/v1/ipam/scan")
