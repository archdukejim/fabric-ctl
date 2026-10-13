from webui.agentclient.connection import call_agent


def scannable_subnets():
    """Purpose: The subnets the console may scan: those this site's DHCP serves, each at most a /22 (decision
             2.1.10.26). Agent route: GET /v1/ipam/scan (dhcp:read).
    Inputs:  none.
    Returns: {"subnets": [{"name", "cidr", "vlan", "hosts"}]} (fabriclib.ipam.scannable_subnets).
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400), AuthError (401),
             PermissionDenied (403).
    Feeds:   src/webui/routes/networks_scan_page."""
    return call_agent("GET", "/v1/ipam/scan")
