from webui.agentclient.connection import call_agent


def site_overview():
    """Purpose: The Directory's Sites (manual 1.6.12.8): each site with its people, machines, DCs, the grants scoped
             to it and its AD site (read-only); the domain's DCs as counts and this DC's replication.
             Agent route: GET /v1/sites (domain:read).
    Inputs:  none.
    Returns: {"sites": [{"name", "group", "people", "machines", "dcs", "grants", "ad"}], "dc_text", "replication",
             "error"}.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400), AuthError (401),
             PermissionDenied (403).
    Feeds:   src/webui/routes/sites_page (/directory/sites).
    """
    return call_agent("GET", "/v1/sites")
