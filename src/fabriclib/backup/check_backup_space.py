import os
import subprocess

from fabriclib.common.errors import ValidationError


def _used(paths):
    """Purpose: bytes the folders use on disk.
    Inputs:  paths — absolute folders.
    Returns: int (0 for none).
    Fails:   never: a folder du cannot read counts what it could.
    Feeds:   check_backup_space."""
    if not paths:
        return 0
    res = subprocess.run(["du", "-sbc", *paths], capture_output=True, text=True)
    last = res.stdout.strip().splitlines()[-1:] or ["0"]
    return int(last[0].split()[0])


def check_backup_space(folder, paths):
    """Purpose: refuse a bundle the disk cannot hold (manual 1.3.7.4): the folder needs twice what the sections'
             folders use free (the sections are staged, then put into the bundle).
    Inputs:  folder — the backups folder (made if missing); paths — every folder the bundle packs.
    Returns: (needed, free) in bytes.
    Fails:   ValidationError naming both sizes when too little is free; OSError from statvfs.
    Feeds:   make_backup."""
    os.makedirs(folder, mode=0o700, exist_ok=True)
    needed = 2 * _used(paths)
    st = os.statvfs(folder)
    free = st.f_bavail * st.f_frsize
    if free < needed:
        raise ValidationError(f"{folder} has {free // 2**20} MiB free; this backup needs {needed // 2**20} MiB "
                              "(twice what it copies). Free some space or remove old bundles first")
    return needed, free
