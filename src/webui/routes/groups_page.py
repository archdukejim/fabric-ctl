import urllib.parse

from webui import agentclient as actions
from webui import views


def groups_page(h, ctx, path, query):
    """Purpose: Directory · Groups (manual 1.6.12.5): /directory/groups (the list: search q, page),
             /directory/groups/_new (Create group) or /directory/groups/<name> (a group's two levels).
    Inputs:  h — the request handler (send, deny); ctx — page context; path — the request's path; query — dict.
    Returns: the page sent; a read fabric-agent refuses or cannot answer (the DC not running, no such group) is said
             on the page.
    Fails:   403 for Create group without groups:admin; 404 for a path with more segments; PermissionDenied and
             AuthError propagate to handle_request.
    Feeds:   get_page."""
    rest = path[len("/directory/groups"):].strip("/")
    if not rest:
        try:
            return h.send(200, views.groups(ctx, "list", groups=actions.list_groups(), query=query))
        except (actions.AgentError, actions.ValidationError) as exc:
            return h.send(200, views.groups(ctx, "list", unavailable=str(exc)))
    if "/" in rest:
        return h.deny(404, "Not found.")
    if rest == "_new":
        if "groups:admin" not in (ctx.get("perms") or ()):
            return h.deny(403, "You need the permission groups:admin to create a group.")
        return h.send(200, views.groups(ctx, "new"))
    name = urllib.parse.unquote(rest)
    try:
        return h.send(200, views.groups(ctx, "group", group=actions.show_group(name)))
    except (actions.AgentError, actions.ValidationError) as exc:
        return h.send(404 if isinstance(exc, actions.NotFound) else 200,
                      views.groups(ctx, "group", group={"name": name}, unavailable=str(exc)))
