import urllib.parse

from webui import agentclient as actions
from webui import views


def _people(ctx):
    """Purpose: The user names a device's owner is chosen from (1.8.6.7): People's, when this person may read them.
    Inputs:  ctx — page context (perms).
    Returns: sorted list of user names, or None (no people:read, or People not readable now: the owner is typed).
    Fails:   never for an agent refusal (None); AuthError propagates.
    Feeds:   devices_page."""
    if "people:read" not in ctx["perms"]:
        return None
    try:
        return sorted(u["uid"] for u in actions.list_people().get("users") or [])
    except (actions.AgentError, actions.ValidationError, actions.PermissionDenied):
        return None


def devices_page(h, ctx, path):
    """Purpose: 802.1X · Devices: /8021x/devices (the list), /8021x/devices/_new (Add device) or /8021x/devices/<name>.
    Inputs:  h — the request handler (send, deny); ctx — page context; path — the request's path.
    Returns: the page sent; devices fabric-agent cannot read are said on the page.
    Fails:   404 for a device that is not there (2.1.8.16) or a longer path; 403 for Add device without
             devices:enroll; PermissionDenied and AuthError propagate to handle_request.
    Feeds:   get_page."""
    rest = path[len("/8021x/devices"):].strip("/")
    if "/" in rest:
        return h.deny(404, "Not found.")
    name = urllib.parse.unquote(rest)
    if name == "_new" and "devices:enroll" not in ctx["perms"]:
        return h.deny(403, "You need the permission devices:enroll to add a device.")
    view = "list" if not name else "new" if name == "_new" else "device"
    try:
        data = actions.device_overview()
    except (actions.AgentError, actions.ValidationError) as exc:
        return h.send(200, views.devices(ctx, view, unavailable=str(exc)))
    device = next((d for d in data["devices"] if d["name"] == name), None) if view == "device" else None
    if view == "device" and device is None:
        return h.deny(404, "No device has that name.")
    people = _people(ctx) if view == "new" or (view == "device" and "devices:admin" in ctx["perms"]) else None
    return h.send(200, views.devices(ctx, view, data=data, device=device, people=people))
