from webui import agentclient as actions
from webui import views


def directory_page(h, ctx, query, status=200):
    """Purpose: Render the Directory's pages and 802.1X's devices and roles: devices, one device, roles, one role,
             the Directory's Overview or Machines (People, Groups, Policies: their own pages).
    Inputs:  h — the request handler (send); ctx — page context; query — dict: view ('device', 'roles', 'role',
             'overview', 'machines', else 'devices'), name (device or
             role); status — int, default 200.
    Returns: the directory page with the given status; when the directory cannot be read (AgentError,
             ValidationError) the page shows why instead of the data. The machines view also shows the site's host
             groups (1.6.11.7; why they could not be read, alone, when that fails).
    Fails:   404 for a device or role that is not there (its page, /8021x/devices/<name>); PermissionDenied and
             AuthError propagate to handle_request (403, redirect to /login).
    Feeds:   get_page (/directory, /directory/machines, /8021x/devices, /8021x/roles).
    """
    view = query.get("view") if query.get("view") in ("device", "roles", "role", "overview", "machines") \
        else "devices"
    kw = {}
    try:
        if view == "machines":
            domain = actions.domain_overview()
            access = {"error": ""}                  # host groups (1.6.11.7); sudo rules are on Policies
            try:
                access.update(groups=actions.list_host_groups())
            except (actions.AgentError, actions.ValidationError) as exc:
                access.update(groups=[], error=str(exc))
            return h.send(status, views.directory(ctx, view, domain=domain, access=access, **kw))
        if view == "overview":
            return h.send(status, views.directory(ctx, view, overview=actions.directory_overview(), **kw))
        data = actions.device_overview()
    except (actions.AgentError, actions.ValidationError) as exc:
        return h.send(status, views.directory(ctx, view, unavailable=str(exc), **kw))
    if view == "device":
        kw["device"] = next((d for d in data["devices"] if d["name"] == query.get("name")), None)
        if not kw["device"]:
            return h.deny(404, "No device has that name.")
    if view == "role":
        kw["role"] = next((r for r in data["roles"] if r["name"] == query.get("name")), None)
        if not kw["role"]:
            return h.deny(404, "No device role has that name.")
    return h.send(status, views.directory(ctx, view, data=data, **kw))
