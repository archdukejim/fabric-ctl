from webui import agentclient as actions
from webui import views


def directory_page(h, ctx, query, status=200):
    """Purpose: Render the Directory tab: devices, one device, roles, one role, people, the domain, machines or Group
             Policy.
    Inputs:  h — the request handler (send); ctx — page context; query — dict: view ('device', 'roles', 'role',
             'people', 'domain', 'machines', 'gpo' (with match: a policy search), else 'devices'), name (device or
             role; unknown → the list), msg, err; status — int, default 200.
    Returns: the directory page with the given status; when the directory cannot be read (AgentError,
             ValidationError) the page shows why instead of the data. The machines view also shows who may sign in
             to them per OU (logon_overview; why it could not be read, alone, when it fails), and the site's host
             groups and sudo rules (1.6.11.7; likewise).
    Fails:   PermissionDenied and AuthError propagate to handle_request (403, redirect to /login).
    Feeds:   get_page (/directory).
    """
    view = query.get("view") if query.get("view") in ("device", "roles", "role", "people", "domain", "machines",
                                                      "gpo") else "devices"
    kw = {"msg": query.get("msg", ""), "err": query.get("err", "")}
    try:
        if view == "machines":                      # who may sign in to them, beside the machines (1.6.11.4)
            domain = actions.domain_overview()
            try:
                logon = actions.logon_overview()
            except (actions.AgentError, actions.ValidationError) as exc:
                logon = {"error": str(exc), "policies": [], "always": [], "legacy": False}
            access = {"error": ""}                  # host groups and sudo rules (1.6.11.7)
            try:
                access.update(groups=actions.list_host_groups(), sudo=actions.list_sudo_rules())
            except (actions.AgentError, actions.ValidationError) as exc:
                access.update(groups=[], sudo=[], error=str(exc))
            return h.send(status, views.directory(ctx, view, domain=domain, logon=logon, access=access, **kw))
        if view == "domain":
            return h.send(status, views.directory(ctx, view, domain=actions.domain_overview(), **kw))
        if view == "gpo":
            return h.send(status, views.directory(ctx, view, gpo=actions.gpo_overview(query.get("match", "")), **kw))
        if view == "people":
            return h.send(status, views.directory(ctx, view, people=actions.list_people(), **kw))
        data = actions.device_overview()
    except (actions.AgentError, actions.ValidationError) as exc:
        return h.send(status, views.directory(ctx, view, unavailable=str(exc), **kw))
    if view == "device":
        kw["device"] = next((d for d in data["devices"] if d["name"] == query.get("name")), None)
        view = view if kw["device"] else "devices"
    if view == "role":
        kw["role"] = next((r for r in data["roles"] if r["name"] == query.get("name")), None)
        view = view if kw["role"] else "roles"
    return h.send(status, views.directory(ctx, view, data=data, **kw))
