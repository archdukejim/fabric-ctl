from webui.agentclient.connection import call_agent


def ssh_overview():
    """Purpose: The SSH page: whether SSH certificates are on, the CA's key, whether the signed-in person may sign
             (manual 1.6.11.9.5).
             Agent route: GET /v1/ssh (any sign-in).
    Inputs:  none.
    Returns: {"on", "public_key", "fingerprint", "may_sign", "why_not", "hours"}.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400), AuthError (401),
             PermissionDenied (403).
    Feeds:   src/webui/routes/ssh_page.
    """
    return call_agent("GET", "/v1/ssh")
