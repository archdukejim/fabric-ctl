import urllib.parse

from webui import agentclient as actions
from webui import views


def sites_page(h, ctx, path):
    """Purpose: Directory · Sites (manual 1.6.12.8): /directory/sites (the list) or /directory/sites/<name> (a site's
             page). Read-only: a site's members are changed on its group's page (Groups), its AD site by fabric.
    Inputs:  h — the request handler (send, deny); ctx — page context; path — the request's path.
    Returns: the page sent; sites fabric-agent cannot read (the DC not running) are said on the page.
    Fails:   404 for a path with more segments; PermissionDenied and AuthError propagate to handle_request.
    Feeds:   get_page."""
    rest = path[len("/directory/sites"):].strip("/")
    if "/" in rest:
        return h.deny(404, "Not found.")
    try:
        overview = actions.site_overview()
    except (actions.AgentError, actions.ValidationError) as exc:
        return h.send(200, views.sites(ctx, name=urllib.parse.unquote(rest), unavailable=str(exc)))
    return h.send(200, views.sites(ctx, overview=overview, name=urllib.parse.unquote(rest)))
