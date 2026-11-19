import glob
import os
import shutil
import subprocess

from fabriclib.common.errors import ValidationError

INSIDE = "/data/.fabric-backup"         # in the samba container: its /data is <base>/samba/data on the host


def dump_directory(base, dest_dir):
    """Purpose: the domain copied while the DC runs (manual 1.3.7.4): `samba-tool domain backup offline`, which copies
             every database under its own locks (consistent, no credentials), and SYSVOL with its ACLs.
    Inputs:  base — the install root (the container's /data is base/samba/data); dest_dir — where the backup's tar
             goes (made; 0700).
    Returns: the path of the tar (samba-backup-<realm>-<time>.tar.bz2) in dest_dir.
    Fails:   ValidationError when samba-tool fails or writes no tar (the DC is not running); OSError.
    Feeds:   backup_plan (the directory section online). Restored by restore_directory."""
    host_side = os.path.join(base, "samba", "data", ".fabric-backup")
    shutil.rmtree(host_side, ignore_errors=True)
    res = subprocess.run(["docker", "exec", "samba", "sh", "-c",
                          f"mkdir -m 0700 {INSIDE} && samba-tool domain backup offline --targetdir={INSIDE}"],
                         capture_output=True, text=True, timeout=1800)
    made = glob.glob(os.path.join(host_side, "samba-backup-*.tar.bz2"))
    try:
        if res.returncode != 0 or not made:
            raise ValidationError(f"the domain could not be copied: {(res.stderr or res.stdout).strip()[-300:]}")
        os.makedirs(dest_dir, mode=0o700, exist_ok=True)
        dest = os.path.join(dest_dir, os.path.basename(made[0]))
        shutil.move(made[0], dest)
        os.chmod(dest, 0o600)
        return dest
    finally:
        shutil.rmtree(host_side, ignore_errors=True)
