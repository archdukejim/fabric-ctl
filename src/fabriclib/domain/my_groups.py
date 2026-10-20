from fabriclib.common.errors import ValidationError
from fabriclib.grants.grant_request import grant_request


def my_groups(v, user, container="samba"):
    """Purpose: "Groups I manage" (manual 1.8.6.6, 2.1.6.67): each group whose managers name the person (or a group
             they are in), with its members and its controls, nothing else about it.
    Inputs:  v — rendered vars; user — the signed-in person's user name (None: root, who manages no group); container —
             the DC's container.
    Returns: {"groups": [{"name", "add", "remove", "only_from", "members"}]}.
    Fails:   ValidationError "a person's own groups: sign in as them" for root; grant_request's (the DC not running).
    Feeds:   agent route GET /v1/account/groups."""
    if not user:
        raise ValidationError("a person's own groups: sign in as them")
    return grant_request(v, {"op": "managed", "user": user}, container)
