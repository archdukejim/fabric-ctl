import grp

from fabriclib.localadmin.constants import ADMIN_GROUPS


def admin_group():
    """Purpose: the group that gives local-admin its sudo here: `sudo` (Debian, Ubuntu), else `wheel`.
    Inputs:  none (the group database).
    Returns: str, or None when neither exists.
    Fails:   never.
    Feeds:   ensure_local_admin, consent/plan_local_admin."""
    for name in ADMIN_GROUPS:
        try:
            grp.getgrnam(name)
            return name
        except KeyError:
            continue
    return None
