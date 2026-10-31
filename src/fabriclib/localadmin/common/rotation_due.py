import datetime

from fabriclib.localadmin.common.utc_now import parse_time
from fabriclib.localadmin.constants import GRACE_HOURS


def rotation_due(record):
    """Purpose: when the host's local-admin gets its next password (manual 1.7.1.4.3, 1.7.1.4.4): the grace after the
             first use or check-out of the current password, whichever came first; both policies of 0.8.0 alike
             (2.1.7.16: neither rotates on a schedule).
    Inputs:  record — load_record's.
    Returns: (aware datetime, why str "used" or "checked out"), or (None, None) when nothing marks it.
    Fails:   ValueError for a stored time that is not one.
    Feeds:   check_local_admin, local_admin_status."""
    marks = []
    if record.get("used"):
        marks.append((parse_time(record["used"]["when"]), "used"))
    if record.get("checkout"):
        marks.append((parse_time(record["checkout"]["when"]), "checked out"))
    if not marks:
        return None, None
    when, why = min(marks)
    return when + datetime.timedelta(hours=GRACE_HOURS), why
