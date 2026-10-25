from webui.agentclient.connection import call_agent
from webui.agentclient.quote_segment import quote_segment


def show_grant(name):
    """Purpose: One grant's page (manual 1.6.13.7): its who, rights and where, and the people and machines it reaches
             by name, the sets of machines it is part of and its computed groups.
             Agent route: GET /v1/domain/grants/<name> (domain:read).
    Inputs:  name — the grant's name (quoted: a name with a slash cannot reach another route).
    Returns: list_grants' row with "who_people", "where_machines", "where_people_names", "sets", "groups",
             "sudo_rule".
    Fails:   the call_agent exceptions: ValidationError (400: no such grant, the DC not running), AgentError,
             AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/access_page (/directory/access/<name>).
    """
    return call_agent("GET", f"/v1/domain/grants/{quote_segment(name)}")
