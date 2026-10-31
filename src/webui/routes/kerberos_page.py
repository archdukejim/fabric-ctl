from webui import agentclient as actions
from webui import views


def kerberos_page(h, ctx):
    """Purpose: Directory · Kerberos (manual 1.6.12.9): /directory/kerberos.
    Inputs:  h — the request handler (send); ctx — page context.
    Returns: the page sent; an overview fabric-agent cannot read is said on the page, and the SPNs a DC that is not
             running cannot list are said in their card.
    Fails:   PermissionDenied and AuthError propagate to handle_request.
    Feeds:   get_page."""
    try:
        overview = actions.kerberos_overview()
    except (actions.AgentError, actions.ValidationError) as exc:
        return h.send(200, views.kerberos(ctx, unavailable=str(exc)))
    try:
        spns, error = actions.list_spns(), ""
    except (actions.AgentError, actions.ValidationError) as exc:
        spns, error = None, str(exc)
    return h.send(200, views.kerberos(ctx, overview, spns, spns_error=error))
