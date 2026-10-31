import os

import yaml

from fabriclib.setup.detach.constants import RECORD


def write_run(config_dir, record):
    """Purpose: save the record of setup's run (manual 1.3.2.3.3) atomically, so the console following it and a
             later setup read the old record or the new one, never a part of either.
    Inputs:  config_dir — the install's config folder (created 0750 if missing); record — dict (no secret in it).
    Returns: the record's path (str); the file is 0600, root's.
    Fails:   OSError writing; yaml errors for values YAML cannot dump.
    Feeds:   detach/hand_over, detach/run_worker, setup/run_steps (after each step)."""
    os.makedirs(config_dir, mode=0o750, exist_ok=True)
    path = os.path.join(config_dir, RECORD)
    tmp = f"{path}.tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            yaml.safe_dump(record, f, sort_keys=False)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return path
