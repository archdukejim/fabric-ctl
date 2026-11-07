from webui import agentclient as actions
from webui import views
from webui.routes.places_for import places_for

MOVABLE = ("person", "group", "machine")


def tree_page(h, ctx, query):
    """Purpose: Directory · Browse (manual 1.8.8.4): /directory/tree?ou=<path> opens the tree to an OU and lists its
             contents; q searches them (whole=1: the whole domain); internal=1 shows the grants' computed groups
             (1.8.8.3); move=<kind>:<name> shows Move to... for one object (1.8.8.5, 2.1.8.37), its choices the OUs the
             DC says the kind may be put in (places_for). Links only: it works without script.
    Inputs:  h — the request handler (send); ctx — page context; query — dict: ou, q, whole, internal, move, page.
    Returns: the page sent; an OU that is not there is a 404 with the DC's words (2.1.8.16); the tree fabric-agent
             cannot read is said on the page.
    Fails:   PermissionDenied and AuthError propagate to handle_request.
    Feeds:   get_page."""
    ou = str(query.get("ou") or "").strip("/")
    q = str(query.get("q") or "").strip()
    whole, internal = str(query.get("whole") or "") == "1", str(query.get("internal") or "") == "1"
    kind, _, name = str(query.get("move") or "").partition(":")
    move = {"kind": kind, "name": name, "places": places_for(kind)} if kind in MOVABLE and name else None
    try:
        tree = actions.browse_ou(ou, q, whole=whole and bool(q), internal=internal)
    except actions.ValidationError as exc:
        missing = str(exc).startswith("no OU")
        return h.send(404 if missing else 200, views.tree(ctx, query=query, unavailable=str(exc)))
    except actions.AgentError as exc:
        return h.send(200, views.tree(ctx, query=query, unavailable=str(exc)))
    return h.send(200, views.tree(ctx, tree=tree, query=query, move=move))
