import re

from agent.kept_store import KEPT
from fabriclib.common.errors import ValidationError
from fabriclib.rbac.required_permission import required_permission

READ_RE = re.compile(r"^[A-Za-z0-9._@-]+(/[A-Za-z0-9._@-]+){0,5}$")


def post_kept(data, perms, user):
    """Purpose: POST /v1/kept/refresh (session; manual 1.8.9.4, decision 2.1.8.45): read one page's data again now.
             Whoever asks must be allowed the read itself, so a person's own read is theirs alone.
    Inputs:  data — {"read": the agent route, e.g. "sites" or "domain/grants/explain/pat"}; perms — the token's
             permissions (None for a root peer); user — the token's user.
    Returns: KeptReads.refresh_now's dict.
    Fails:   ValidationError: no such route, a read this person may not make (saying which permission), nothing kept
             under it, or asked again within the class's lower limit (saying when).
    Feeds:   agent/post_route."""
    read = data.get("read")
    if not isinstance(read, str) or not READ_RE.match(read):
        raise ValidationError("read: which page's data to refresh")
    route = read.split("/")
    need = required_permission("GET", route)
    if need is None:
        raise ValidationError(f"no such read: {read}")
    if perms is not None and need != "session" and need not in perms:
        raise ValidationError(f"you need the permission {need}")
    if route == ["account", "groups"]:              # kept per person, as get_route keeps it
        return KEPT.refresh_now(("account", "groups", user))
    return KEPT.refresh_now(tuple(route))
