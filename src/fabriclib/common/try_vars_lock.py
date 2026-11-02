import fcntl
import os

from fabriclib.common.paths import VARS_LOCK_FILE


def try_vars_lock(path=VARS_LOCK_FILE):
    """Purpose: the settings' lock (vars_lock's), taken without waiting: an apply holding it reads the plan itself, so
             the plan poll skips a round and Sync now is refused.
    Inputs:  path — the lock file.
    Returns: the open lock file (held until it is closed), or None when another process holds it.
    Fails:   OSError creating the file.
    Feeds:   ipam/poll_plan, ipam/sync/sync_plan."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    lock = open(path, "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock.close()
        return None
    return lock
