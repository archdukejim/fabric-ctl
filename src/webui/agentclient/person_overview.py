from webui.agentclient.connection import call_agent
from webui.agentclient.quote_segment import quote_segment


def person_overview(uid):
    """Purpose: One person's page (manual 1.6.12.4): their details as the DC has them, state, last sign-in, groups,
             sites, the certificates fabric issued them and the 802.1X devices they own.
             Agent route: GET /v1/people/<uid> (people:read).
    Inputs:  uid — the user name (quoted: a name with a slash cannot reach another route).
    Returns: {"uid", "person": {field: value}, "groups", "state", "last_logon", "sites", "certs", "devices"}.
    Fails:   the call_agent exceptions: ValidationError (400: no such person in OU=people, the DC not running),
             AgentError, AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/people_page (/directory/people/<uid>), directory_post (an edit's changed fields).
    """
    return call_agent("GET", f"/v1/people/{quote_segment(uid)}")
