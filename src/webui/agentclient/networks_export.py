from webui.agentclient.connection import call_agent
from webui.agentclient.quote_segment import quote_segment


def networks_export(site):
    """Purpose: A site's address table as CSV, for the Networks page's export (manual 1.10.4.21.1). Agent route: GET
             /v1/networks/<site>/export (dhcp:read), timeout 60 s.
    Inputs:  site — a site's name (the page passes the one it shows).
    Returns: {"csv": str, "name": the file name}.
    Fails:   the call_agent exceptions: AgentError, NotFound (404: no such site), ValidationError (400: the domain
             not answering: an export is never of a stale copy), AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/networks_page (/networks/export)."""
    return call_agent("GET", f"/v1/networks/{quote_segment(site)}/export", timeout=60)
