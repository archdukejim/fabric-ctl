from webui import agentclient as actions
from webui import views


def options_page(h, ctx, query):
    """Purpose: Render the DHCP options page (manual 1.10.4.24.6), a page of its own under the Kea tab until it drops
             into the Networks tab: the organisation's and the site's options, definitions and classes, each subnet's
             and reservation's options and netboot preset, and the effective options of a chosen subnet or address
             with their sources.
    Inputs:  h — the request handler (send); ctx — page context; query — dict: site (default this site), target
             ("site", "subnet:<name>", "address:<ip>"), msg, err.
    Returns: 200 page.
    Fails:   agent errors propagate to handle_request (400: another site's from a site not at the top, an unknown
             target; redirect to /login, 403, 503).
    Feeds:   get_page (/kea/options)."""
    site = query.get("site", "")
    overview = actions.option_sets(site or "-", query.get("target", ""))
    return h.send(200, views.dhcp_options(ctx, overview, query.get("target", ""), query.get("msg", ""),
                                          query.get("err", "")))
