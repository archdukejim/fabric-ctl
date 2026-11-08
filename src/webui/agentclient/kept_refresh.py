from webui.agentclient.connection import call_agent


def kept_refresh(read):
    """Purpose: Read one page's kept data again now (manual 1.8.9.4). Agent route: POST /v1/kept/refresh (session; the
             agent also checks the read's own permission).
    Inputs:  read — the agent route of the data, e.g. "sites".
    Returns: {"age_s", "failed"}.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400: asked too soon,
             says when; nothing kept; not this person's read), AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/kept_post."""
    return call_agent("POST", "/v1/kept/refresh", {"read": read})
