from webui.agentclient.connection import call_agent


def host_reminders():
    """Purpose: what every administrator is reminded of on this host (2.1.6.69): the break-glass password's file still
             on it. Agent route: GET /v1/reminders (status:read).
    Inputs:  none.
    Returns: list of {"kind", "text"}; [] when there is nothing to remind.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400), AuthError (401),
             PermissionDenied (403).
    Feeds:   src/webui/session/finish_login (the top bar, from each sign-in), src/webui/routes/get_page for "/".
    """
    return call_agent("GET", "/v1/reminders")
