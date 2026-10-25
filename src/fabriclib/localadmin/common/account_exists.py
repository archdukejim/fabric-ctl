import pwd

from fabriclib.localadmin.constants import USER


def account_exists(name=USER):
    """Purpose: whether a local account of that name exists on this host (the passwd database).
    Inputs:  name — the account (default local-admin).
    Returns: bool.
    Fails:   never.
    Feeds:   checkout_local_admin, ensure_local_admin, remove_local_admin, local_admin_checks, local_admin_status."""
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False
