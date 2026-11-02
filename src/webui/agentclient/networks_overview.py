from webui.agentclient.connection import call_agent
from webui.agentclient.quote_segment import quote_segment


def networks_overview(site=""):
    """Purpose: What the Networks page shows of one site (manual 1.10.4.40.1): every site of the domain, the site's
             VLANs and subnets drawn as maps, its address table, options and their sources, the Sync now card's state
             (this site) and the scans requested there. Agent route: GET /v1/networks[/<site>] (dhcp:read), 60 s.
    Inputs:  site — a site's name ("" this install's own).
    Returns: fabriclib.ipam.networks_overview's dict.
    Fails:   the call_agent exceptions: AgentError, NotFound (404: no such site in the domain), ValidationError
             (400: the DC not answering for another site), AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/networks_page."""
    return call_agent("GET", "/v1/networks" + (f"/{quote_segment(site)}" if site else ""), timeout=60)
