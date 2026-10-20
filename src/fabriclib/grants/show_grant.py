from fabriclib.grants.grant_request import grant_request


def show_grant(v, name, container="samba"):
    """Purpose: one grant (manual 1.6.13.7): its who, rights and where, the people and machines it reaches by name, its
             computed groups, the sets of machines it is part of and its sudo rule.
    Inputs:  v — rendered vars; name — the grant's name; container — the DC's container.
    Returns: the grant's summary (grants_tool's show).
    Fails:   ValidationError "no grant <name>", or from grant_request.
    Feeds:   agent route GET /v1/domain/grants/<name> (domain:read); grants/run_grant_command (`grant show`)."""
    return grant_request(v, {"op": "show", "name": name}, container)
