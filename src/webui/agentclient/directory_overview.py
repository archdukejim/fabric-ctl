from webui.agentclient.connection import call_agent


def directory_overview():
    """Purpose: The Directory's Overview (manual 1.6.12.3): the domain, its functional level and DCs, the five roles,
             replication, the sites and the counts. Agent route: GET /v1/directory (domain:read).
    Inputs:  none.
    Returns: dict from fabriclib.domain.directory_overview: status, level, dcs, replication, sites, counts, error.
    Fails:   the call_agent exceptions: AgentError, ValidationError (400), AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/directory_page (view "overview", /directory).
    """
    return call_agent("GET", "/v1/directory")
