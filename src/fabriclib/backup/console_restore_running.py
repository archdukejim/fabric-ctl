import os
import subprocess

from fabriclib.backup.make_bundle import FOLDER

UNIT = "fabric-console-restore"                      # the console's whole restore (manual 1.3.7.9)
LOG = os.path.join(FOLDER, "console-restore.log")


def console_restore_running(run=subprocess.run):
    """Purpose: whether the console's whole restore runs now (its unit fabric-console-restore active).
    Inputs:  run — subprocess.run (tests).
    Returns: True or False (no systemd: False).
    Fails:   never.
    Feeds:   start_console_restore, agent/get_backup."""
    try:
        res = run(["systemctl", "is-active", "--quiet", UNIT], capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False
    return res.returncode == 0
