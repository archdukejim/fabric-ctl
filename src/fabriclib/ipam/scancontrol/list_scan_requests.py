import time

from fabriclib.ipam.scancontrol.limits import KEEP, RUN_WITHIN
from fabriclib.ipam.scancontrol.read_scan_requests import read_scan_requests


def list_scan_requests(v, site="", secrets=None, container="samba", requests=read_scan_requests, now=time.time):
    """Purpose: a site's scan requests and their answers, as `fabricctl ipam scan-requests` shows them (decision
             2.1.10.38, manual 1.10.4.36): newest first; a request older than a day (the serving site's poll removes
             it) left out; a pending one older than an hour marked as not picked up. Any site's: every DC reads the
             plan, and the requests are below it.
    Inputs:  v — fabric vars (site_name); site — the site ("" this one); secrets, container — as read_scan_requests;
             requests, now — read_scan_requests and time.time (tests give their own).
    Returns: list of read_scan_requests' rows, each with "age" (seconds) and "late" (bool: pending past the hour).
    Fails:   ValidationError from the read (the DC not answering, no such site).
    Feeds:   run_scan_command (scan-requests, and scan --site's wait)."""
    which = str(site or "").strip() or v["site_name"]
    out = []
    for r in requests(v, which, secrets, container):
        age = now() - r["created_at"]
        if age > KEEP:
            continue
        out.append({**r, "age": int(age), "late": r["state"] == "pending" and age > RUN_WITHIN})
    return sorted(out, key=lambda r: (-r["created_at"], r["id"]))
