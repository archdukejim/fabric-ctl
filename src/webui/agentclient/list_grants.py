from webui.agentclient.connection import call_agent


def list_grants():
    """Purpose: The domain's grants and the templates a new one may start from (manual 1.6.13.7).
             Agent route: GET /v1/domain/grants (domain:read).
    Inputs:  none.
    Returns: {"grants": [{"name", "kind", "description", "who", "where", "people", "machines", "signin", "sudo",
             "local_admin", "reaches_nobody", "counts": {"people", "machines", "where_people"}}], "templates": {name:
             its fields}}.
    Fails:   the call_agent exceptions: ValidationError (400: the DC not running), AgentError, AuthError (401),
             PermissionDenied (403).
    Feeds:   src/webui/routes/access_page (/directory/access).
    """
    return call_agent("GET", "/v1/domain/grants")
