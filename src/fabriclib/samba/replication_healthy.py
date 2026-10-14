import datetime

MAX_AGE = 3600          # seconds: every inbound partner must have succeeded within the last hour


def replication_healthy(status, now=None, max_age=MAX_AGE):
    """Purpose: whether this DC's replication is healthy enough to change a DC's type (decision 2.1.9.23, manual
             1.9.8.20.2): it could be asked, it has at least one inbound partner, and every partner of every partition
             succeeded within max_age seconds with no failure since.
    Inputs:  status — samba/replication_status's {"neighbours": [{"partition", "from", "last_success" ("YYYY-MM-DD
             HH:MM:SS UTC" or "" for never), "failures", "message"}], "error"}; now — aware datetime (tests);
             max_age — seconds.
    Returns: (bool, str): (True, "") or (False, why, naming the partner and its failure).
    Fails:   never.
    Feeds:   federation/request_dc_type, federation/change_dc_type."""
    if status.get("error"):
        return False, f"this domain controller could not be asked: {status['error']}"
    neighbours = status.get("neighbours") or []
    if not neighbours:
        return False, "this domain controller replicates with no other"
    now = now or datetime.datetime.now(datetime.timezone.utc)
    for n in neighbours:
        partner = f"{n.get('from', '?')} ({n.get('partition', '?')})"
        if int(n.get("failures") or 0):
            return False, f"{partner} has failed {n['failures']} time(s) since its last success: {n.get('message', '')}"
        try:
            last = datetime.datetime.strptime(n.get("last_success") or "", "%Y-%m-%d %H:%M:%S UTC").replace(
                tzinfo=datetime.timezone.utc)
        except ValueError:
            return False, f"{partner} has never replicated"
        if (now - last).total_seconds() > max_age:
            return False, f"{partner} last replicated at {n['last_success']}, more than {max_age // 60} minutes ago"
    return True, ""
