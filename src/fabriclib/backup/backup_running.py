import fcntl
import os

from fabriclib.backup.backup_lock import LOCK


def backup_running(path=LOCK):
    """Purpose: whether a backup or restore holds its lock now (manual 1.3.7.4), so setup, --apply, an image update or
             another restore can refuse instead of changing what is being copied.
    Inputs:  path — the lock file.
    Returns: the holder's pid (str) when one runs, else None.
    Fails:   never (no lock file: none runs).
    Feeds:   run_backup_command, the agent's backup routes."""
    try:
        fd = os.open(path, os.O_RDWR)
    except OSError:
        return None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        held = os.read(fd, 32).decode(errors="replace").strip()
        os.close(fd)
        return held or "?"
    fcntl.flock(fd, fcntl.LOCK_UN)
    os.close(fd)
    return None
