from webui.agentclient.connection import call_agent


def list_spns():
    """Purpose: The domain's service principals (manual 1.6.12.9), read-only, each with the account it is on; a
             duplicate (which breaks Kerberos for both accounts) flagged.
             Agent route: GET /v1/domain/kerberos/spns (domain:read).
    Inputs:  none.
    Returns: {"spns": [{"spn", "account", "kind", "duplicate"}], "duplicates": [spn]}.
    Fails:   the call_agent exceptions: ValidationError (400: the DC not running), AgentError, AuthError (401),
             PermissionDenied (403).
    Feeds:   src/webui/routes/kerberos_page (/directory/kerberos).
    """
    return call_agent("GET", "/v1/domain/kerberos/spns")
