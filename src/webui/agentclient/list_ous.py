from webui.agentclient.connection import call_agent


def list_ous():
    """Purpose: The tree of the domain's folders (manual 1.6.12.7): every OU by its path, fabric's fixed ones marked,
             an admin's own changeable, with what each holds directly.
             Agent route: GET /v1/ous (domain:read).
    Inputs:  none.
    Returns: {"ous": [{"path", "dn", "fabric", "own", "holds": {"people", "groups", "computers", "ous", "other"}}]}.
    Fails:   the call_agent exceptions: ValidationError (400: the DC not running), AgentError, AuthError (401),
             PermissionDenied (403).
    Feeds:   src/webui/routes/ous_page (/directory/ous).
    """
    return call_agent("GET", "/v1/ous")
