import contextlib
import os
import subprocess

from fabriclib.common.errors import ValidationError


@contextlib.contextmanager
def mounted_stick(v, fs_path, name, writable=False):
    """Purpose: context manager that mounts a key stick's file system for a with block and always unmounts it after.
    Inputs:  v — vars: openbao_runtime_dir (the mount point is its sibling usb-<name>, a RAM path, made 0700);
             fs_path — device node holding the file system; name — the slot id, used in the mount point's name;
             writable — mount read-write (default read-only). Always nosuid,nodev,noexec. Needs root.
    Returns: yields the mount point (str); afterwards it flushes the stick's file system alone (`sync -f`: a plain
             `sync` waits on every file system the host has, and hung on one in the tests, 2.3.1.30), unmounts it and
             removes the folder.
    Fails:   ValidationError "cannot mount" when mount fails; OSError if the mount point cannot be made.
             Unmount and rmdir failures are ignored (the folder then stays).
    Feeds:   slots/usb wrap, unwrap and forget.
    """
    point = os.path.join(os.path.dirname(v["openbao_runtime_dir"].rstrip("/")), f"usb-{name}")
    os.makedirs(point, mode=0o700, exist_ok=True)
    opts = ("rw" if writable else "ro") + ",nosuid,nodev,noexec"
    res = subprocess.run(["mount", "-o", opts, fs_path, point], capture_output=True, text=True)
    if res.returncode != 0:
        raise ValidationError(f"cannot mount {fs_path}: {res.stderr.strip()[-200:]}")
    try:
        yield point
    finally:
        subprocess.run(["sync", "-f", point], capture_output=True)      # this file system only
        subprocess.run(["umount", point], capture_output=True)
        try:
            os.rmdir(point)
        except OSError:
            pass
