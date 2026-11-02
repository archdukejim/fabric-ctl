from webui import agentclient as actions
from webui import views


def options_page(h, ctx, query):
    """Purpose: DHCP · DHCP options (GET /networks/options, manual 1.10.4.40.1): the domain's and a site's option
             sets (?site=, this one by default), each subnet's and reservation's, and a target's effective options
             with their sources and, for a subnet or reservation, its own forms (?target=site|subnet:<name>|
             address:<ip>). A subnet or reservation is looked up first, so one not there answers 404.
    Inputs:  h — the request handler (send, deny); ctx — page context; query — dict: site, target.
    Returns: 200 page; 404 for a site, subnet or reservation that is not there (decision 2.1.8.16).
    Fails:   agent errors propagate to handle_request (400 a target of another kind or the DC not answering, 403,
             503).
    Feeds:   get_page."""
    site, target = query.get("site", ""), query.get("target", "")
    try:
        overview = actions.option_sets(site)
        views.option_owner(overview, target)
    except actions.NotFound as exc:
        return h.deny(404, f"Not found: {exc}.")
    except LookupError as exc:
        return h.deny(404, f"Not found: {exc.args[0]}.")
    if target:
        overview = actions.option_sets(site, target)
    return h.send(200, views.dhcp_options(ctx, overview, target))
