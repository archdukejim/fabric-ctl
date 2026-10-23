from webui.agentclient.connection import call_agent
from webui.agentclient.quote_segment import quote_segment


def explain_grants(person):
    """Purpose: Which grants reach a person, and why (manual 1.6.13.7): for a person's page.
             Agent route: GET /v1/domain/grants/explain/<person> (domain:read).
    Inputs:  person — the user name (quoted).
    Returns: {"person", "never" (why no grant reaches them, or ""), "grants": [{"name", "kind", "who_missing",
             "reaches", "rights"}]}.
    Fails:   the call_agent exceptions: ValidationError (400: no such person, the DC not running), AgentError,
             AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/people_page (a person's page).
    """
    return call_agent("GET", f"/v1/domain/grants/explain/{quote_segment(person)}")
