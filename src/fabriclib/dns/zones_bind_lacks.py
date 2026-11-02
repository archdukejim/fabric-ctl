import os
import subprocess

# each zone BIND answers "not found" for, one name a line; any other failure (BIND not running) names none
_SCRIPT = ('for z; do out=$(rndc zonestatus "$z" 2>&1) || case "$out" in *"not found"*) echo "$z";; esac; done')


def zones_bind_lacks(data_dir, run=subprocess.run):
    """Purpose: the zones fabric has a file for that a running BIND does not know: a zone list installed without
             `rndc reconfig` (an apply stopped after BIND's files were in place, 2.3.10.11.16), which no later apply
             would reconfigure for, since the list is then unchanged.
    Inputs:  data_dir — a folder of zone files named db.<zone> (the render's bind9/data); run — subprocess.run or a
             stand-in.
    Returns: sorted list of zone names BIND answered "not found" for; [] when BIND is not running or not answering
             (nothing to tell then: its start reads the list), or when there are no zone files.
    Fails:   never raises: OSError and a timeout (60 s) give [].
    Feeds:   deploy/install_bind9_files (counts the configuration changed, so BIND is reconfigured)."""
    try:
        zones = sorted(n[3:] for n in os.listdir(data_dir) if n.startswith("db.") and not n.endswith(".jnl"))
    except OSError:
        return []
    if not zones:
        return []
    try:
        res = run(["docker", "exec", "-u", "bind", "bind9", "sh", "-c", _SCRIPT, "sh", *zones],
                  capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return []
    named = set(zones)
    return sorted({x.strip() for x in str(getattr(res, "stdout", "") or "").splitlines()} & named)
