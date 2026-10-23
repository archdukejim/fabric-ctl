import urllib.parse

from webui import agentclient as actions
from webui import views


def radius_page(h, ctx, path):
    """Purpose: 802.1X's RADIUS clients page and its own pages: /8021x/clients/_new (Add RADIUS client),
             /8021x/clients/<name>, /8021x/people/_new (Map a group), /8021x/people/<group>.
    Inputs:  h — the request handler (send, deny); ctx — page context; path — the request's path.
    Returns: the page sent.
    Fails:   404 for a client or mapping that is not there (2.1.8.16) or another path; 403 for an add page without
             radius:admin; agent errors propagate to handle_request.
    Feeds:   get_page."""
    parts = [urllib.parse.unquote(x) for x in path.split("/")[2:]]
    if len(parts) != 2 or parts[0] not in ("clients", "people") or not parts[1]:
        return h.deny(404, "Not found.")
    kind, name = parts
    if name == "_new":
        if "radius:admin" not in ctx["perms"]:
            return h.deny(403, "You need the permission radius:admin for this page.")
        return h.send(200, views.freeradius(ctx, actions.radius_overview(),
                                            view="new-client" if kind == "clients" else "new-mapping"))
    overview = actions.radius_overview()
    if kind == "clients":
        client = next((c for c in overview.get("clients") or [] if c["name"] == name), None)
        if client is None:
            return h.deny(404, "No RADIUS client has that name.")
        return h.send(200, views.freeradius(ctx, overview, view="client", client=client))
    mapping = next((m for m in overview.get("people") or [] if m["group"] == name), None)
    if mapping is None:
        return h.deny(404, "No group of that name is mapped.")
    return h.send(200, views.freeradius(ctx, overview, view="mapping", mapping=mapping))
