from webui.agentclient.connection import call_agent
from webui.agentclient.quote_segment import quote_segment


def rodc_lost_plan(site):
    """Purpose: every account a site's lost read-only DC held the password of, and what handling it would do
             (decision 2.1.6.58). Agent route: GET /v1/federation/rodc-lost/<site> (system:admin).
    Inputs:  site — the site (quoted).
    Returns: dict, plan_rodc_lost's answer.
    Fails:   the call_agent exceptions: AgentError, ValidationError (400: not below this site, this DC read-only, the
             DC does not answer), AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/get_page (/federation?rodc_lost=<site>)."""
    return call_agent("GET", f"/v1/federation/rodc-lost/{quote_segment(site)}")
