import os
import shutil

from fabriclib.common.same_content import same_content


def copy_if_changed(src, dst, mode, uid=0, gid=0):
    """Purpose: install one file when its content differs from what is there (byte for byte, 2.3.1.29).
    Inputs:  src, dst — file paths; mode — int; uid, gid — owner (default root).
    Returns: True if dst was missing or different and has been replaced (mode and owner set), else False.
    Fails:   OSError from comparing, copying, chown or chmod.
    Feeds:   deploy/* (compose files, systemd units, nginx.conf, webui.json)."""
    if os.path.exists(dst) and same_content(src, dst):
        return False
    shutil.copy2(src, dst)
    os.chmod(dst, mode)
    os.chown(dst, uid, gid)
    return True
