import datetime


def utc_now():
    """Purpose: the time now, in UTC, as the local-admin record and OpenBao's versions keep it.
    Inputs:  none.
    Returns: an aware datetime.datetime (UTC, whole seconds).
    Fails:   never.
    Feeds:   every local-admin function that records a time."""
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)


def parse_time(text):
    """Purpose: a time the record keeps (ISO 8601 with its offset) read back.
    Inputs:  text — str, or None.
    Returns: an aware datetime.datetime, or None for None or "".
    Fails:   ValueError for a text that is not such a time.
    Feeds:   check_local_admin, local_admin_status, local_admin_warnings."""
    return datetime.datetime.fromisoformat(text) if text else None
