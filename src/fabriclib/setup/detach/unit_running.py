import subprocess

from fabriclib.setup.detach.constants import RUNNING_STATES, UNIT


def unit_running(run=subprocess.run):
    """Purpose: whether setup's unit, fabric-setup.service, runs now (decision 2.1.2.26).
    Inputs:  run — subprocess.run (tests give their own).
    Returns: True when `systemctl is-active` says active, activating, deactivating, reloading or refreshing (its
             process may still run or write its log); False otherwise, also when the unit is unknown (a finished
             unit is unloaded: --collect) or systemctl is missing.
    Fails:   never — a missing systemctl reads as not running.
    Feeds:   setup/run_setup (choose_start), detach/follow_run (when to stop following)."""
    try:
        r = run(["systemctl", "is-active", UNIT], capture_output=True, text=True)
    except OSError:
        return False
    return (r.stdout or "").strip() in RUNNING_STATES
