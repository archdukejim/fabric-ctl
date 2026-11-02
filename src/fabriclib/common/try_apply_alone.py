import fcntl
import os

from fabriclib.common.paths import APPLY_INTENT_FILE


def try_apply_alone(path=APPLY_INTENT_FILE):
    """Purpose: the intent file held alone, taken without waiting (decision 2.1.10.45): None while an apply runs or a
             change an apply follows is being made (apply_intent), so the plan poll leaves that change to its apply.
    Inputs:  path — the intent file.
    Returns: the open file (held alone until it is closed), or None when another holds it.
    Fails:   OSError creating the file.
    Feeds:   ipam/poll_plan."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    lock = open(path, "a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock.close()
        return None
    return lock
