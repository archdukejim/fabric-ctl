import time

from fabriclib.ipam.common.site_scope import site_scope
from fabriclib.ipam.scancontrol.limits import KEEP, RUN_WITHIN
from fabriclib.ipam.scancontrol.read_scan_requests import read_scan_requests


def list_scan_requests(v, site="", secrets=None, container="samba", requests=read_scan_requests, scope=site_scope,
                       now=time.time):
    """Purpose: a site's scan requests and their answers, as the asking console and `fabricctl ipam scan-requests`
             show them (decision 2.1.10.30, manual 1.10.4.29.3): newest first; a request older than a day (the branch's
             poll removes it) left out; a pending one older than an hour marked as not picked up.
    Inputs:  v — fabric vars (site_name); site — the site ("" this one; another only when it is below this one:
             site_scope); secrets, container — as read_scan_requests; requests, scope, now — read_scan_requests,
             site_scope and time.time (tests give their own).
    Returns: list of read_scan_requests' rows, each with "age" (seconds) and "late" (bool: pending past the hour).
    Fails:   ValidationError from site_scope (a site not below this one) or the read (the DC not answering).
    Feeds:   run_scan_command (scan-requests, and scan --site's wait), networks_overview (a site below)."""
    which = scope(v, site)
    out = []
    for r in requests(v, which, secrets, container):
        age = now() - r["created_at"]
        if age > KEEP:
            continue
        out.append({**r, "age": int(age), "late": r["state"] == "pending" and age > RUN_WITHIN})
    return sorted(out, key=lambda r: (-r["created_at"], r["id"]))
