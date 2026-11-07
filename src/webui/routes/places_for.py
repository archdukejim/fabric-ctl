from webui import agentclient as actions


def places_for(kind):
    """Purpose: the OUs a create form's Create in... offers for a kind (manual 1.8.8.5, 2.1.6.101): those the DC says
             it may be given (list_ous' "kinds", may_hold's rule), so the choices follow that rule wherever it is
             widened. Without the tree (the DC not answering) the form keeps fabric's own folder, its default.
    Inputs:  kind — "person", "machine" or "group".
    Returns: list of str, OU paths, by path.
    Fails:   PermissionDenied and AuthError propagate (the caller's page decides); AgentError and
             ValidationError give [].
    Feeds:   people_page, groups_page, computers_page (the "new" views)."""
    try:
        tree = actions.list_ous()
    except (actions.AgentError, actions.ValidationError):
        return []
    return [o["path"] for o in tree.get("ous") or [] if kind in (o.get("kinds") or [])]
