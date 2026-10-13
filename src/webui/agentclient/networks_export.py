from webui.agentclient.connection import call_agent
from webui.agentclient.quote_segment import quote_segment


def networks_export(site):
    """Purpose: A site's address table as CSV, for the Networks tab's export. Agent route: GET
             /v1/networks/<site>/export (dhcp:read), timeout 60 s.
    Inputs:  site — a site's name.
    Returns: {"csv": str, "name": the file name}.
    Fails:   the call_agent exceptions: AgentError, ValidationError (400: the site, or the domain not answering),
             AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/networks_page (/networks/export)."""
    return call_agent("GET", f"/v1/networks/{quote_segment(site)}/export", timeout=60)
