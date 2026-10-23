import urllib.parse

from webui import agentclient as actions
from webui import views


def computers_page(h, ctx, path, query):
    """Purpose: Directory · Computers (manual 1.6.12.6): /directory/computers (the list: search q, type, site, page),
             /directory/computers/_new (Add computer), /directory/computers/_groups (the Machine groups tab) or
             /directory/computers/<name> (a computer's page). "_new" and "_groups" are never a host name (a host name
             has no underscore).
    Inputs:  h — the request handler (send, deny); ctx — page context; path — the request's path; query — dict.
    Returns: the page sent; a read fabric-agent refuses or cannot answer (the DC not running, no such machine) is said
             on the page.
    Fails:   403 for Add computer without machines:admin; 404 for a path with more segments; PermissionDenied and
             AuthError propagate to handle_request.
    Feeds:   get_page."""
    rest = path[len("/directory/computers"):].strip("/")
    if "/" in rest:
        return h.deny(404, "Not found.")
    if rest == "_new":
        if "machines:admin" not in (ctx.get("perms") or ()):
            return h.deny(403, "You need the permission machines:admin to add a computer.")
        return h.send(200, views.computers(ctx, "new"))
    try:
        if not rest:
            return h.send(200, views.computers(ctx, "list", machines=actions.list_machines(), query=query))
        if rest == "_groups":
            return h.send(200, views.computers(ctx, "groups", groups=actions.list_host_groups(),
                                               machines=actions.list_machines()))
    except (actions.AgentError, actions.ValidationError) as exc:
        return h.send(200, views.computers(ctx, "groups" if rest else "list", unavailable=str(exc)))
    name = urllib.parse.unquote(rest)
    try:
        return h.send(200, views.computers(ctx, "computer", computer=actions.machine_overview(name)))
    except (actions.AgentError, actions.ValidationError) as exc:
        return h.send(200, views.computers(ctx, "computer", computer={"machine": {"name": name}},
                                           unavailable=str(exc)))
