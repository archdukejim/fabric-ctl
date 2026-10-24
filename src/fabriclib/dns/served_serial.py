import re

from fabriclib.dns.rndc import rndc


def served_serial(zone, call=None):
    """Purpose: ask BIND9 which SOA serial it currently serves for a zone (`rndc zonestatus`).
    Inputs:  zone — zone name; call — the rndc runner, or None for dns/rndc (looked up at the call).
    Returns: the serial as a string, or None if rndc failed, timed out or printed no serial.
    Fails:   never raises — rndc failures become None.
    Feeds:   reload_zone (to confirm the new file is being served); apply_dns (its health gate); find_changed_zones
             (a deployed file BIND did not load), from deploy/install_bind9_files and dns/publish_plan_records."""
    try:
        res = (call or rndc)(["zonestatus", zone])
    except OSError:                          # no docker here: nothing answers
        return None
    m = re.search(r"^serial: (\d+)", str(getattr(res, "stdout", "") or ""), re.MULTILINE)
    return m.group(1) if m else None
