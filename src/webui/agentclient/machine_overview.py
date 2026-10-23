from webui.agentclient.connection import call_agent
from webui.agentclient.quote_segment import quote_segment


def machine_overview(name):
    """Purpose: One computer's page (manual 1.6.12.6): its facts, the grants that reach it and what each gives, the
             802.1X device of the same name, and the sites, machine groups and folders its actions choose from.
             Agent route: GET /v1/machines/<name> (domain:read).
    Inputs:  name — the computer's host name (quoted: a name with a slash cannot reach another route).
    Returns: {"machine", "grants", "devices", "choices": {"sites", "groups", "folders"}}.
    Fails:   the call_agent exceptions: ValidationError (400: no such machine, the DC not running), AgentError,
             AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/computers_page (/directory/computers/<name>).
    """
    return call_agent("GET", f"/v1/machines/{quote_segment(name)}")
