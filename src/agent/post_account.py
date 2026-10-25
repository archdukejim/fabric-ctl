from agent.read_text import read_text
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.domain.change_own_password import change_own_password


def post_account(route, caller, data, session):
    """Purpose: a person's own account (manual 1.8.6.6): POST /v1/account/password (body: current, new), any
             signed-in person, for themselves only (the token's user, never a name in the body); done at once, never
             pending (2.1.8.9), their sessions elsewhere ended.
    Inputs:  route — ["account", "password"]; caller — the token's user (None: a root peer, refused); data — the
             body; session — the token's `sid`, the session kept.
    Returns: {"uid", "changed", "sessions_ended"}.
    Fails:   ValidationError (-> 400): "unknown operation", or change_own_password's (root, a wrong current password,
                 the
             policy).
    Feeds:   agent/post_route.py (POST account/...)."""
    if route == ["account", "password"]:
        return change_own_password(load_vars(), caller, read_text(data, "current"), read_text(data, "new"), session)
    raise ValidationError("unknown operation")
