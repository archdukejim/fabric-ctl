import os

import yaml

from fabriclib.setup.detach.constants import HANDOFF_DIR, HANDOFF_SUFFIX


def write_handoff(run_id, secrets, directory=HANDOFF_DIR):
    """Purpose: hand the secrets typed in setup's questions to its unit (manual 1.3.2.3.4): never on the unit's
             command line or in its environment, which `systemctl show` prints to any user, but in a file only
             root can read, made new for this run.
    Inputs:  run_id — the run's id (names the file); secrets — {name: str}, e.g. admin_password,
             join_invitation; directory — where (default /run/fabric-setup, tmpfs; created when missing and
             kept 0700).
    Returns: the file's path (str): <directory>/setup-<run_id>.handoff, 0600, created with O_EXCL and O_NOFOLLOW so
             an existing file or a planted symlink is refused, never written through.
    Fails:   FileExistsError when the file exists; OSError creating or writing (a part-written file is removed);
             ValueError for a run_id holding a path separator.
    Feeds:   detach/hand_over; read by detach/read_handoff in the unit."""
    if not run_id or os.sep in run_id or run_id.startswith("."):
        raise ValueError(f"not a run id: {run_id!r}")
    os.makedirs(directory, mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    path = os.path.join(directory, f"setup-{run_id}{HANDOFF_SUFFIX}")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            yaml.safe_dump(dict(secrets), f)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        os.remove(path)
        raise
    return path
