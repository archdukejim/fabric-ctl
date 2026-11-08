from webui.agentclient.connection import call_agent


def updates_read():
    """Purpose: The Updates page's kept data (manual 1.8.9.2): the image rows.
             Agent route: GET /v1/updates (status:read).
    Inputs:  none.
    Returns: {"rows": image rows as image_rows gives them, "kept": {"age_s", "failed"} when served from what was kept}.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400), AuthError (401),
             PermissionDenied (403).
    Feeds:   src/webui/routes/get_page for /overview/updates."""
    return call_agent("GET", "/v1/updates")
