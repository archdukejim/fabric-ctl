from webui import agentclient as actions
from webui import views


def lifetimes_page(h, ctx):
    """Purpose: PKI → Lifetimes (decision 2.1.5.14, manual 1.5.1.10): /pki/lifetimes.
    Inputs:  h — the request handler (send); ctx — page context (its pending changes give the page's Apply bar).
    Returns: the page sent; lifetimes fabric-agent cannot read are said on the page.
    Fails:   PermissionDenied and AuthError propagate to handle_request.
    Feeds:   get_page."""
    try:
        life, error = actions.read_lifetimes(), ""
    except (actions.AgentError, actions.ValidationError) as exc:
        life, error = None, str(exc)
    return h.send(200, views.lifetimes(ctx, life, unavailable=error))
