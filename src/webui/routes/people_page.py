import urllib.parse

from webui import agentclient as actions
from webui import views


def people_page(h, ctx, path, query):
    """Purpose: Directory · People (manual 1.6.12.4): /directory/people (the list: search q, page), /directory/people/
             _new (Add person) or /directory/people/<uid> (a person's page).
    Inputs:  h — the request handler (send, deny); ctx — page context; path — the request's path; query — dict.
    Returns: the page sent; a read fabric-agent refuses or cannot answer (the DC not running, no such person) is
             said on the page.
    Fails:   403 for Add person without people:create; 404 for a path with more segments; PermissionDenied and
             AuthError propagate to handle_request.
    Feeds:   get_page."""
    rest = path[len("/directory/people"):].strip("/")
    if not rest:
        try:
            return h.send(200, views.people(ctx, "list", people=actions.list_people(), query=query))
        except (actions.AgentError, actions.ValidationError) as exc:
            return h.send(200, views.people(ctx, "list", unavailable=str(exc)))
    if "/" in rest:
        return h.deny(404, "Not found.")
    if rest == "_new":
        if "people:create" not in (ctx.get("perms") or ()):
            return h.deny(403, "You need the permission people:create to add a person.")
        return h.send(200, views.people(ctx, "new"))
    uid = urllib.parse.unquote(rest)
    try:
        person = actions.person_overview(uid)
    except (actions.AgentError, actions.ValidationError) as exc:
        return h.send(200, views.people(ctx, "person", person={"uid": uid}, unavailable=str(exc)))
    try:
        groups = actions.list_people() if "people:groups" in (ctx.get("perms") or ()) else None
    except (actions.AgentError, actions.ValidationError):
        groups = None
    return h.send(200, views.people(ctx, "person", people=groups, person=person))
