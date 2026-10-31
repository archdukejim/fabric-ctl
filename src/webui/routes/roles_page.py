import urllib.parse

from webui import agentclient as actions
from webui import views


def roles_page(h, ctx, path):
    """Purpose: 802.1X · Device roles: /8021x/roles (the list), /8021x/roles/_new (Add device role) or
             /8021x/roles/<name>.
    Inputs:  h — the request handler (send, deny); ctx — page context; path — the request's path.
    Returns: the page sent; roles fabric-agent cannot read are said on the page.
    Fails:   404 for a role that is not there (2.1.8.16) or a longer path; 403 for Add device role without
             roles:admin; PermissionDenied and AuthError propagate to handle_request.
    Feeds:   get_page."""
    rest = path[len("/8021x/roles"):].strip("/")
    if "/" in rest:
        return h.deny(404, "Not found.")
    name = urllib.parse.unquote(rest)
    if name == "_new" and "roles:admin" not in ctx["perms"]:
        return h.deny(403, "You need the permission roles:admin to add a device role.")
    view = "list" if not name else "new" if name == "_new" else "role"
    try:
        data = actions.device_overview()
    except (actions.AgentError, actions.ValidationError) as exc:
        return h.send(200, views.roles(ctx, view, unavailable=str(exc)))
    role = next((r for r in data["roles"] if r["name"] == name), None) if view == "role" else None
    if view == "role" and role is None:
        return h.deny(404, "No device role has that name.")
    return h.send(200, views.roles(ctx, view, data=data, role=role))
