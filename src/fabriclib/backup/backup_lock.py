import contextlib
import fcntl
import os

from fabriclib.common.errors import ValidationError

LOCK = "/run/fabric/backup.lock"


@contextlib.contextmanager
def backup_lock(what="a backup", path=LOCK):
    """Purpose: one backup or restore at a time (manual 1.3.7.4): an exclusive lock on LOCK for as long as the block
             runs; the lock goes with the process, so a killed run leaves none behind.
    Inputs:  what — what takes it, for the refusal ("a backup", "a restore"); path — the lock file (tests).
    Returns: a context manager; inside it the lock is held.
    Fails:   ValidationError when another backup or restore holds it (naming its pid, written in the file).
    Feeds:   make_backup, restore_section, restore_bundle; backup_running reads the same file."""
    os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            held = os.read(fd, 32).decode(errors="replace").strip()
            raise ValidationError(f"{what} cannot start: a backup or restore is running (pid {held or '?'}); "
                                  "wait for it to finish") from None
        os.ftruncate(fd, 0)
        os.write(fd, str(os.getpid()).encode())
        yield
    finally:
        os.close(fd)
