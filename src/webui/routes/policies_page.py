from webui import agentclient as actions
from webui import views


def policies_page(h, ctx, path, query):
    """Purpose: Directory · Policies (manual 1.6.12.10): /directory/policies (the password policy),
             /directory/policies/gpo (Group Policy; query match: a search of the templates) or /directory/policies/sudo
             (the sudo rules).
    Inputs:  h — the request handler (send); ctx — page context; path — one of the three; query — dict.
    Returns: the page sent; a read fabric-agent refuses or cannot answer is said on the page (the sudo rules' reads:
             in their card).
    Fails:   PermissionDenied and AuthError propagate to handle_request.
    Feeds:   get_page."""
    view = {"/directory/policies/gpo": "gpo", "/directory/policies/sudo": "sudo"}.get(path, "password")
    try:
        if view == "password":
            return h.send(200, views.policies(ctx, view, domain=actions.domain_overview()))
        if view == "gpo":
            return h.send(200, views.policies(ctx, view, gpo=actions.gpo_overview(query.get("match", ""))))
        access = {"error": ""}
        try:
            access.update(groups=actions.list_host_groups(), sudo=actions.list_sudo_rules())
        except (actions.AgentError, actions.ValidationError) as exc:
            access.update(groups=[], sudo=[], error=str(exc))
        return h.send(200, views.policies(ctx, view, access=access))
    except (actions.AgentError, actions.ValidationError) as exc:
        return h.send(200, views.policies(ctx, view, unavailable=str(exc)))
