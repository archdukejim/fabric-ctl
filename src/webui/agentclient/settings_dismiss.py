from webui.agentclient.connection import call_agent


def settings_dismiss():
    """Purpose: dismiss the setup wizard (manual 1.8.5.3): the first sign-in no longer opens it and the Overview no
             longer shows Finish setting up; Settings still opens it. Agent route: POST /v1/settings/dismiss
             (settings:admin).
    Inputs:  none.
    Returns: {"how", "by", "at"} as recorded.
    Fails:   the call_agent exceptions: AgentError, ValidationError (400), AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/settings_post (/settings/dismiss).
    """
    return call_agent("POST", "/v1/settings/dismiss", {})
