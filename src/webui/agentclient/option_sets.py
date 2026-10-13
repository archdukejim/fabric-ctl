from webui.agentclient.connection import call_agent
from webui.agentclient.quote_segment import quote_segment


def option_sets(site, target=""):
    """Purpose: What the DHCP options page shows (manual 1.10.4.24.6), read-only: the organisation's and the site's
             option sets, each subnet's and reservation's options and netboot preset, and given a target its effective
             options with their sources. Agent route: GET /v1/ipam/options/<site>[/<target>] (dhcp:read).
    Inputs:  site — the site's name; target — "", "site", "subnet:<name>" or "address:<ip>".
    Returns: options_overview's dict (fabriclib.ipam.options.options_overview).
    Fails:   the call_agent exceptions: AgentError, ValidationError (400: e.g. another site's from a site not at the
             top), AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/options_page."""
    path = f"/v1/ipam/options/{quote_segment(site)}" + (f"/{quote_segment(target)}" if target else "")
    return call_agent("GET", path)
