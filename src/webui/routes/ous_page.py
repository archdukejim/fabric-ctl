from webui import agentclient as actions
from webui import views


def ous_page(h, ctx, query):
    """Purpose: Directory · OUs (manual 1.6.12.7): /directory/ous (the tree) or /directory/ous?ou=<path> (one OU's
             page; an OU is named by its path, which holds slashes, so it is the query's, not the address's).
    Inputs:  h — the request handler (send); ctx — page context; query — dict: ou.
    Returns: the page sent; a tree fabric-agent cannot read (the DC not running) is said on the page; an OU that is not
             in the tree is said on its page, a 404 (2.1.8.16).
    Fails:   PermissionDenied and AuthError propagate to handle_request.
    Feeds:   get_page."""
    path = str(query.get("ou") or "").strip("/")
    try:
        tree = actions.list_ous()
    except (actions.AgentError, actions.ValidationError) as exc:
        return h.send(200, views.ous(ctx, path=path, unavailable=str(exc)))
    there = not path or any(o["path"] == path for o in tree.get("ous") or [])
    return h.send(200 if there else 404, views.ous(ctx, tree=tree, path=path))
