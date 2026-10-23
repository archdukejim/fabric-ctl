import urllib.parse

from webui import agentclient as actions
from webui import views


def access_page(h, ctx, path, query):
    """Purpose: Directory · Access (manual 1.6.13.7): /directory/access (the grants: search q, page),
             /directory/access/_new (Add grant; query template: the template it starts from) or
             /directory/access/<name> (a grant's page).
    Inputs:  h — the request handler (send, deny); ctx — page context; path — the request's path; query — dict.
    Returns: the page sent; a read fabric-agent refuses or cannot answer (the DC not running, no such grant) is said
             on the page.
    Fails:   403 for Add grant without groups:admin; 404 for a path with more segments; PermissionDenied and
             AuthError propagate to handle_request.
    Feeds:   get_page."""
    rest = path[len("/directory/access"):].strip("/")
    if "/" in rest:
        return h.deny(404, "Not found.")
    if rest == "_new" and "groups:admin" not in (ctx.get("perms") or ()):
        return h.deny(403, "You need the permission groups:admin to add a grant.")
    if not rest or rest == "_new":
        view = "new" if rest else "list"
        try:
            return h.send(200, views.access(ctx, view, grants=actions.list_grants(), query=query))
        except (actions.AgentError, actions.ValidationError) as exc:
            return h.send(200, views.access(ctx, view, unavailable=str(exc)))
    name = urllib.parse.unquote(rest)
    try:
        return h.send(200, views.access(ctx, "grant", grant=actions.show_grant(name)))
    except (actions.AgentError, actions.ValidationError) as exc:
        return h.send(404 if isinstance(exc, actions.NotFound) else 200,
                      views.access(ctx, "grant", grant={"name": name}, unavailable=str(exc)))
