import contextlib
import subprocess

from fabriclib.common.systemctl_up import systemctl_up


@contextlib.contextmanager
def pause_unit(unit):
    """Purpose: a service stopped for the time its files are copied, then started again (manual 1.3.7.4: Step-CA's
             database cannot be read while it writes), started again even when the copy fails.
    Inputs:  unit — the systemd unit (stepca).
    Returns: a context manager.
    Fails:   CalledProcessError when the unit cannot be stopped (nothing is copied) or started again
             (systemctl_up waits out a start cut short).
    Feeds:   backup_plan (the pki section online)."""
    active = subprocess.run(["systemctl", "is-active", "--quiet", unit]).returncode == 0
    if active:
        subprocess.run(["systemctl", "stop", unit], check=True, capture_output=True)
    try:
        yield
    finally:
        if active:
            systemctl_up([unit], capture=True)
