from webui.agentclient.connection import call_agent
from webui.agentclient.quote_segment import quote_segment


def networks_overview(site=""):
    """Purpose: What the Networks tab shows of one site: its VLANs, subnets drawn as maps, the address table, options
             and their sources. Agent route: GET /v1/networks[/<site>] (dhcp:read), timeout 60 s.
    Inputs:  site — a site's name ("" this install's own).
    Returns: fabriclib.ipam.networks_overview's dict.
    Fails:   the call_agent exceptions: AgentError, ValidationError (400: a site this console does not show),
             AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/networks_page."""
    return call_agent("GET", "/v1/networks" + (f"/{quote_segment(site)}" if site else ""), timeout=60)
