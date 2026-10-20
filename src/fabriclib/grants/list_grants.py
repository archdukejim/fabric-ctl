from fabriclib.grants.grant_request import grant_request


def list_grants(v, container="samba"):
    """Purpose: the domain's grants and the templates (manual 1.6.13.7): each grant's who, rights and where, whom it
             reaches as counts, and whether it reaches nobody.
    Inputs:  v — rendered vars; container — the DC's container.
    Returns: {"grants": [grant summaries], "templates": {name: rights}}.
    Fails:   ValidationError from grant_request (the DC not running).
    Feeds:   agent route GET /v1/domain/grants (domain:read); grants/run_grant_command (`grant list`)."""
    return grant_request(v, {"op": "list"}, container)
