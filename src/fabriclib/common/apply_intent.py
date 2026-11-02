import fcntl
import os
from contextlib import contextmanager

from fabriclib.common.paths import APPLY_INTENT_FILE


@contextmanager
def apply_intent(path=APPLY_INTENT_FILE):
    """Purpose: say "an apply is running or about to run" for as long as the body runs (decision 2.1.10.45, manual
             1.10.4.42): a shared lock on the intent file, which any number of applies and changes hold at once and
             the plan poll can take alone only when none does (try_apply_alone). The lock goes with the process, so a
             crash leaves nothing stale.
    Inputs:  path — the intent file (default APPLY_INTENT_FILE; created, and its folder, if missing).
    Returns: a context manager; the body runs while the shared lock is held.
    Fails:   OSError creating the file; it waits while the plan poll holds the file alone (seconds: one Kea render).
             Exceptions from the body propagate after the lock is released.
    Feeds:   deploy/apply_deployment (every apply), ipam/run_ipam_command (a change to the plan from the CLI),
             agent/post_route (the address manager's changes) and agent/post_pending (a page's Apply)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_SH)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
