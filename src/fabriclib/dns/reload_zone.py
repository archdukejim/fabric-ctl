import os
import re
import time

from fabriclib.dns.install_zone_file import install_zone_file
from fabriclib.dns.rndc import rndc


def file_serial(path):
    """Purpose: read the SOA serial from a zone file (the line "<n> ; Serial").
    Inputs:  path — zone file path.
    Returns: the serial as a string, or None if there is no such line.
    Fails:   OSError if the file cannot be read.
    Feeds:   reload_zone (the serial BIND must end up serving); tests/zone_test.py."""
    m = re.search(r"^\s*(\d+)\s*;\s*Serial", open(path).read(), re.MULTILINE)
    return m.group(1) if m else None


def _served_serial(zone):
    """Purpose: ask BIND9 which SOA serial it currently serves for a zone (`rndc zonestatus`).
    Inputs:  zone — zone name.
    Returns: the serial as a string, or None if rndc failed, timed out or printed no serial.
    Fails:   never raises — rndc failures become None.
    Feeds:   reload_zone (to confirm the new file is being served)."""
    res = rndc(["zonestatus", zone])
    m = re.search(r"^serial: (\d+)", res.stdout if res else "", re.MULTILINE)
    return m.group(1) if m else None


def _serial_above(src, served):
    """Purpose: make the rendered file's SOA serial greater than the one BIND serves: a dynamic zone's serial grows
             with every DHCP registration, and can pass the render's (the epoch, 1.10.3.4), and BIND keeps a file
             whose serial is not greater ("zone serial unchanged").
    Inputs:  src — the rendered file (rewritten in place when needed); served — BIND's serial (str) or None.
    Returns: the serial src now carries (str), or None when it has none.
    Fails:   OSError reading or writing src.
    Feeds:   reload_zone."""
    want = file_serial(src)
    if not want or not served or int(want) > int(served):
        return want
    text = open(src).read()
    new = str(int(served) + 1)
    with open(src, "w") as f:
        f.write(re.sub(r"^(\s*)" + want + r"(\s*;\s*Serial)", lambda m: m.group(1) + new + m.group(2), text, count=1,
                       flags=re.MULTILINE))
    return new


def reload_zone(zone, src, dst, uid, gid):
    """Purpose: swap a zone file under a running BIND9 and make sure BIND serves the new one.
    Inputs:  zone — zone name; src — rendered file; dst — deployed file; uid, gid — bind user's ids. Needs the bind9
             container running.
    Returns: None. Dynamic zones are frozen, swapped and thawed; static zones (freeze fails) swapped and reloaded.
             Retried up to 5 times until `rndc zonestatus` shows src's serial, which is first made greater than
             the one BIND serves (_serial_above: Kea's registrations raise a dynamic zone's).
    Fails:   never raises for BIND errors: prints "Warning: BIND9 did not accept zone ..." or "... serves <zone> serial
             X, not Y" and returns. OSError from install_zone_file propagates.
    Feeds:   deploy/install_zones_and_restart (live zone updates); tests/zone_test.py.
    Notes:   freezing makes BIND write its in-memory copy to the file, and that write can land after ours and put the
             old zone back ("zone serial unchanged" on thaw), hence the serial check and retry."""
    print(f"Updating zone {zone}...")
    want = _serial_above(src, _served_serial(zone))
    res = None
    for attempt in range(5):
        frozen = rndc(["freeze", zone])
        if attempt:
            time.sleep(1)                      # let BIND finish writing its copy
        install_zone_file(src, dst, uid, gid)
        jnl = dst + ".jnl"
        if os.path.exists(jnl):
            os.remove(jnl)
        if frozen is not None and frozen.returncode == 0:
            res = rndc(["thaw", zone])
        else:
            # Static zone (no update-policy): a plain reload is enough.
            res = rndc(["reload", zone])
        if res is None or res.returncode != 0 or not want or _served_serial(zone) == want:
            break
        print(f"  BIND9 still serves the old {zone} (its own write raced ours); again")
    if res is None or res.returncode != 0:
        why = (res.stderr or res.stdout).strip() if res else "timeout"
        print(f"  Warning: BIND9 did not accept zone {zone}: {why}")
    elif want and _served_serial(zone) != want:
        print(f"  Warning: BIND9 serves {zone} serial {_served_serial(zone)}, not {want}")
