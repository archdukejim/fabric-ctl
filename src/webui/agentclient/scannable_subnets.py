from webui.agentclient.connection import call_agent


def scannable_subnets():
    """Purpose: The subnets the console may scan: every subnet of this site's plan, DHCP on or off, each at most a /22
             (decisions 2.1.10.26, 2.1.10.28), and whether this site's own admins may scan here (2.1.10.30). Agent
             route: GET /v1/ipam/scan (dhcp:read).
    Inputs:  none.
    Returns: {"subnets": [{"name", "cidr", "vlan", "dhcp", "hosts"}], "local": {"site", "top", "allowed", "set_by",
             "source", "why", "stale"} or None, "local_error"} (fabriclib.ipam.scan_overview).
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400), AuthError (401),
             PermissionDenied (403).
    Feeds:   src/webui/routes/networks_scan_page."""
    return call_agent("GET", "/v1/ipam/scan")
