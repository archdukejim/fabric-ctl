from webui import agentclient as actions
from webui import views
from webui.routes.one_site import ONE_SITE, other_site


def options_page(h, ctx, query):
    """Purpose: Networks · DHCP options (GET /networks/options, manual 1.10.4.40.1): this site's option set, with the
             domain's values it inherits shown (2.1.10.64; ?site= may name only this site, 1.8.6.14), each
             subnet's and reservation's, and a target's effective options with their sources and, for a subnet or
             reservation, its own forms (?target=site|subnet:<name>|address:<ip>). A subnet or reservation is
             looked up first, so one not there answers 404.
    Inputs:  h — the request handler (send, deny); ctx — page context; query — dict: site, target.
    Returns: 200 page; 404 for a subnet or reservation that is not there (decision 2.1.8.16), and for another site
             (ONE_SITE, 2.1.8.68).
    Fails:   agent errors propagate to handle_request (400 a target of another kind or the DC not answering, 403,
             503).
    Feeds:   get_page."""
    site, target = query.get("site", ""), query.get("target", "")
    try:
        # this site's only (1.8.6.14): a site named is checked first, by the plan's own read, so another site's
        # answers 404 even when the option sets cannot be read here
        if site and other_site(site, actions.networks_overview().get("site")):
            return h.deny(404, ONE_SITE + ".")
        overview = actions.option_sets("")
        views.option_owner(overview, target)
    except actions.NotFound as exc:
        return h.deny(404, f"Not found: {exc}.")
    except LookupError as exc:
        return h.deny(404, f"Not found: {exc.args[0]}.")
    if target:
        overview = actions.option_sets("", target)
    return h.send(200, views.dhcp_options(ctx, overview, target))
