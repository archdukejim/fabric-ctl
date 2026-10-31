from webui.agentclient.connection import call_agent


def list_groups():
    """Purpose: The site's groups for Directory · Groups (manual 1.6.12.5): each one's kind, member count and
             description. Agent route: GET /v1/groups (domain:read).
    Inputs:  none.
    Returns: {"groups": [{"name", "kind", "members", "description"}]}.
    Fails:   the call_agent exceptions: AgentError, ValidationError (400: the DC not running), AuthError (401),
             PermissionDenied (403).
    Feeds:   src/webui/routes/groups_page.
    """
    return call_agent("GET", "/v1/groups")
