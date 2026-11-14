import subprocess


def rndc(args, timeout=15):
    """Purpose: run an rndc command inside the bind9 container as the bind user.
    Inputs:  args — list of rndc arguments (e.g. ["freeze", zone]; zone names come from validated vars); timeout —
             seconds, default 15.
    Returns: the subprocess.CompletedProcess (not checked: callers read returncode/stdout/stderr), or None on a timeout.
             A zone command BIND refuses because the zone is in several views (split DNS, 2.1.4.16: shared
             with in-view) is run again naming the view that holds it, `IN default`.
    Fails:   never raises for a failed command; prints "rndc <args> timed out" and returns None on a timeout.
    Feeds:   reload_zone, deploy/install_zones_and_restart (freeze before a restart, `rndc reconfig`)."""
    try:
        res = subprocess.run(["docker", "exec", "-u", "bind", "bind9", "rndc", *args],
                             capture_output=True, text=True, timeout=timeout)
        if len(args) == 2 and res.returncode != 0 and "multiple views" in (res.stdout or "") + (res.stderr or ""):
            # split DNS (2.1.4.16): a zone shared into a VLAN's view is named with the view that holds it
            res = subprocess.run(["docker", "exec", "-u", "bind", "bind9", "rndc", *args, "IN", "default"],
                                 capture_output=True, text=True, timeout=timeout)
        return res
    except subprocess.TimeoutExpired:
        print(f"rndc {' '.join(args)} timed out")
        return None
