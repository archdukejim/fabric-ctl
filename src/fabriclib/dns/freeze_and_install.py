import os
import time

from fabriclib.dns.install_zone_file import install_zone_file
from fabriclib.dns.rndc import rndc


def _mtime(path):
    """Purpose: a file's modification time in nanoseconds, or None when it is not there.
    Inputs:  path — str.
    Returns: int or None.
    Fails:   never.
    Feeds:   freeze_and_install."""
    try:
        return os.stat(path).st_mtime_ns
    except OSError:
        return None


def freeze_and_install(zone, src, dst, uid, gid, wait=3.0):
    """Purpose: put a rendered zone file in place under a running BIND that is about to restart (manual 1.4.1,
             2.3.10.10.4): freeze the zone so BIND writes its journal into the file (what DHCP and RFC2136 registered,
             2.1.10.7), wait until that write has landed, then install the new file. `rndc freeze` answers before
             BIND's write is done; installed at once, the new file was replaced by BIND's copy of the old zone a moment
             later, and the restart then loaded the old zone (a changed setting's record not served).
    Inputs:  zone — zone name; src — rendered file; dst — deployed file; uid, gid — the bind user's ids; wait — how
             long to wait for BIND's write (seconds). Only a journal newer than the file holds changes BIND will
             write (seen in the sandbox: with none, a freeze writes nothing); otherwise there is no wait.
    Returns: True when BIND's write was seen before the install, or none was due (no journal newer than the file, or
             the freeze failed: a static zone); False when none came within `wait`.
    Fails:   OSError from install_zone_file.
    Feeds:   deploy/finish_without_start (setup), deploy/restart_changed (an apply that restarts bind9)."""
    before = _mtime(dst)
    jnl = _mtime(dst + ".jnl")
    pending = jnl is not None and (before is None or jnl > before)   # changes the file does not hold yet
    res = rndc(["freeze", zone])
    seen = res is None or res.returncode != 0 or not pending
    end = time.monotonic() + wait
    while not seen and time.monotonic() < end:
        if _mtime(dst) != before:
            seen = True
            break
        time.sleep(0.05)
    install_zone_file(src, dst, uid, gid)
    return seen
