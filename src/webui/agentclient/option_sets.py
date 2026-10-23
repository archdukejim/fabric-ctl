from webui.agentclient.connection import call_agent
from webui.agentclient.quote_segment import quote_segment


def option_sets(site="", target=""):
    """Purpose: What the DHCP options page shows (manual 1.10.4.40.1, 1.10.4.24.6), read-only: the domain's and the
             site's option sets, each subnet's and reservation's options and netboot preset, and given a target its
             effective options with their sources. Agent route: GET /v1/ipam/options/<site>[/<target>] (dhcp:read).
    Inputs:  site — the site's name ("" this site, sent as "-"); target — "", "site", "subnet:<name>" or
             "address:<ip>".
    Returns: options_overview's dict ({"site", "here", "domain", "site_options", "settings", "subnets",
             "catalogue", "effective"}).
    Fails:   the call_agent exceptions: AgentError, NotFound (404: no such site), ValidationError (400: a bad target,
             the DC not answering), AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/options_page."""
    path = f"/v1/ipam/options/{quote_segment(site or '-')}" + (f"/{quote_segment(target)}" if target else "")
    return call_agent("GET", path)
