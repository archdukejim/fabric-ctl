from webui.agentclient.connection import call_agent
from webui.agentclient.quote_segment import quote_segment


def dc_type_request(site, to):
    """Purpose: ask a site below this one to change its DC type (decision 2.1.9.23, revised 2026-10-14: from the
             console too). Agent route: POST /v1/federation/dc-type/<site> (federation:admin).
    Inputs:  site — the site (quoted); to — "writable" or "rodc".
    Returns: dict {"token" (the one-time change token, shown once), "site", "to", "id", "expires", "was"}.
    Fails:   the call_agent exceptions: AgentError, ValidationError (400: request_dc_type's refusals — a site not
             below this one, the type it has already, replication unhealthy, the endpoint off), AuthError (401),
             PermissionDenied (403).
    Feeds:   src/webui/routes/federation_post (/federation/dc-type)."""
    return call_agent("POST", f"/v1/federation/dc-type/{quote_segment(site)}", {"to": to})
