from fabriclib.grants.grant_request import grant_request


def explain_grant(v, person, machine=None, container="samba"):
    """Purpose: which grants reach a person, and on a machine, and why (manual 1.6.13.7): for each grant the who (and
             where) groups they are missing; on a machine, the person's sign-in, local administrator and sudo there.
    Inputs:  v — rendered vars; person — a user name; machine — a computer's short name, or None; container — the DC's
             container.
    Returns: grants_tool's explain result.
    Fails:   ValidationError "no person … in the domain", "no machine … in the domain", or from grant_request.
    Feeds:   agent routes GET /v1/domain/grants/explain/<person>[/<machine>] (domain:read); grants/run_grant_command
             (`grant explain`)."""
    return grant_request(v, {"op": "explain", "person": person, "machine": machine}, container)
