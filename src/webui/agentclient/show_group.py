from webui.agentclient.connection import call_agent
from webui.agentclient.quote_segment import quote_segment


def show_group(name):
    """Purpose: One group's page in its two levels (manual 1.6.12.5, 2.1.6.67): what it grants, its managers and
             their controls, its members. Agent route: GET /v1/groups/<name> (domain:read).
    Inputs:  name — the group's name (quoted).
    Returns: {"name", "kind", "description", "scope", "managers", "members"}.
    Fails:   the call_agent exceptions: ValidationError (400: no such group, the DC not running), AgentError,
             AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/groups_page.
    """
    return call_agent("GET", f"/v1/groups/{quote_segment(name)}")
