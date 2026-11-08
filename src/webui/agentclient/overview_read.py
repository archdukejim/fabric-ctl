from webui.agentclient.connection import call_agent


def overview_read():
    """Purpose: The Overview's kept data (manual 1.8.9.2): the services and the host's reminders, read together.
             Agent route: GET /v1/overview (status:read).
    Inputs:  none.
    Returns: {"services": [tuples (service, systemd state, container health)], "reminders": [...] or None when they
             could not be read, "kept": {"age_s", "failed"} when served from what was kept}.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400), AuthError (401),
             PermissionDenied (403).
    Feeds:   src/webui/routes/get_page for "/"."""
    out = call_agent("GET", "/v1/overview")
    return {**out, "services": [tuple(x) for x in out["services"]]}
