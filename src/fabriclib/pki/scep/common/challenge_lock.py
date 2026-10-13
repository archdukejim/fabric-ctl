import fcntl
import os
from contextlib import contextmanager


@contextmanager
def challenge_lock(store):
    """Purpose: exclusive lock (context manager) around a read-modify-write of the challenge store, shared by the web
             console's agent and the SCEP hook: a challenge is spent exactly once even when two requests race.
    Inputs:  store — path of the challenge store; the lock is "<folder>/.<file name>.lock" (created, its folder 0700).
    Returns: a context manager; the body runs while the flock is held.
    Fails:   OSError if the lock file or its folder cannot be created; blocks while another process holds it.
    Feeds:   create_challenge, check_challenge, record_scep_issue, withdraw_challenge."""
    folder = os.path.dirname(store)
    os.makedirs(folder, mode=0o700, exist_ok=True)
    fd = os.open(os.path.join(folder, "." + os.path.basename(store) + ".lock"), os.O_WRONLY | os.O_CREAT, 0o600)
    with os.fdopen(fd, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
