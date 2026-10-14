from webui.agentclient.connection import call_agent
from webui.agentclient.quote_segment import quote_segment


def rodc_lost(site, confirm):
    """Purpose: handle a site's lost or stolen read-only DC (decision 2.1.6.58): every account it held reset, the DC
             removed. Agent route: POST /v1/federation/rodc-lost/<site> (system:admin).
    Inputs:  site — the site (quoted); confirm — what the person typed (must be the site's name).
    Returns: dict {"plan", "reset", "removed", "changed"}.
    Fails:   the call_agent exceptions: AgentError, ValidationError (400: the confirmation, and rodc_lost's refusals),
             AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/federation_post (/federation/rodc-lost/<site>)."""
    return call_agent("POST", f"/v1/federation/rodc-lost/{quote_segment(site)}", {"confirm": confirm})
