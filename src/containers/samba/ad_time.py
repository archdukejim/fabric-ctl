import datetime


def ad_time(filetime):
    """Purpose: an AD timestamp (100 ns since 1601: lastLogonTimestamp, pwdLastSet) as ISO text.
    Inputs:  filetime — str or int; "0" or absent for never.
    Returns: str, "" for never.
    Fails:   never (a value that is not a number counts as never).
    Feeds:   list_machines, list_people."""
    try:
        value = int(filetime)
    except (TypeError, ValueError):
        return ""
    if value <= 0:
        return ""
    seconds = value / 10_000_000 - 11644473600
    return datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc).isoformat(timespec="seconds")
