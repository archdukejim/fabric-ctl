import os
import re
import time

from fabriclib.dns.install_zone_file import install_zone_file
from fabriclib.dns.rndc import rndc
from fabriclib.dns.served_serial import served_serial


def file_serial(path):
    """Purpose: read the SOA serial from a zone file (the line "<n> ; Serial").
    Inputs:  path — zone file path.
    Returns: the serial as a string, or None if there is no such line.
    Fails:   OSError if the file cannot be read.
    Feeds:   reload_zone (the serial BIND must end up serving); tests/zone_test.py."""
    m = re.search(r"^\s*(\d+)\s*;\s*Serial", open(path).read(), re.MULTILINE)
    return m.group(1) if m else None


def reload_zone(zone, src, dst, uid, gid):
    """Purpose: swap a zone file under a running BIND9 and make sure BIND serves the new one.
    Inputs:  zone — zone name; src — rendered file; dst — deployed file; uid, gid — bind user's ids. Needs the bind9
             container running.
    Returns: None. Dynamic zones are frozen, swapped and thawed; static zones (freeze fails) swapped and reloaded.
             Retried up to 5 times until `rndc zonestatus` shows src's serial.
    Fails:   never raises for BIND errors: prints "Warning: BIND9 did not accept zone ..." or "... serves <zone> serial
             X, not Y" and returns. OSError from install_zone_file propagates.
    Feeds:   deploy/install_zones_and_restart (live zone updates); tests/zone_test.py.
    Notes:   freezing makes BIND write its in-memory copy to the file, and that write can land after ours and put the
             old zone back ("zone serial unchanged" on thaw), hence the serial check and retry."""
    print(f"Updating zone {zone}...")
    want = file_serial(src)
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
        if res is None or res.returncode != 0 or not want or served_serial(zone) == want:
            break
        print(f"  BIND9 still serves the old {zone} (its own write raced ours); again")
    if res is None or res.returncode != 0:
        why = (res.stderr or res.stdout).strip() if res else "timeout"
        print(f"  Warning: BIND9 did not accept zone {zone}: {why}")
    elif want and served_serial(zone) != want:
        print(f"  Warning: BIND9 serves {zone} serial {served_serial(zone)}, not {want}")
