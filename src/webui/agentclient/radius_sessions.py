from webui.agentclient.connection import call_agent


def radius_sessions():
    """Purpose: The open 802.1X sessions, from accounting, and what can be done to each.
             Agent route: GET /v1/radius/sessions (radius:read).
    Inputs:  none.
    Returns: {"enabled", "sessions": [{"client", "session", "mac", "who", "person", "vlan", "port", "since", "seen",
             "vendor", "actions", "no_coa", ...}], "error"}.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400), AuthError (401),
             PermissionDenied (403).
    Feeds:   src/webui/routes/get_page (/freeradius?view=sessions).
    """
    return call_agent("GET", "/v1/radius/sessions")
