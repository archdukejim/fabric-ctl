from webui.agentclient.connection import call_agent


def logon_overview():
    """Purpose: Who may sign in to the site's machines, per OU (manual 1.6.11.4).
             Agent route: GET /v1/domain/logon (domain:read).
    Inputs:  none.
    Returns: dict from fabriclib.samba.logon_overview: site, legacy (no per-OU policies yet), always, policies
             [{ou, console, remote}], error.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400), AuthError (401),
             PermissionDenied (403).
    Feeds:   src/webui/routes/directory_page (view "machines").
    """
    return call_agent("GET", "/v1/domain/logon")
