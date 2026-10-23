from webui import agentclient as actions
from webui import views


def directory_page(h, ctx):
    """Purpose: The Directory's Overview, /directory (1.6.12.3).
    Inputs:  h — the request handler (send); ctx — page context.
    Returns: the page sent; a directory fabric-agent cannot read is said on the page.
    Fails:   PermissionDenied and AuthError propagate to handle_request (403, redirect to /login).
    Feeds:   get_page (/directory).
    """
    try:
        return h.send(200, views.directory(ctx, overview=actions.directory_overview()))
    except (actions.AgentError, actions.ValidationError) as exc:
        return h.send(200, views.directory(ctx, unavailable=str(exc)))
