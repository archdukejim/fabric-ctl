import re

from fabriclib.dns.rndc import rndc


def served_serial(zone):
    """Purpose: ask BIND9 which SOA serial it currently serves for a zone (`rndc zonestatus`).
    Inputs:  zone — zone name.
    Returns: the serial as a string, or None if rndc failed, timed out or printed no serial.
    Fails:   never raises — rndc failures become None.
    Feeds:   reload_zone (to confirm the new file is being served); apply_dns (its health gate)."""
    res = rndc(["zonestatus", zone])
    m = re.search(r"^serial: (\d+)", res.stdout if res else "", re.MULTILINE)
    return m.group(1) if m else None
