import os
import shutil

from fabriclib.common.same_content import same_content


def copy_tree_with_perms(src, dst, uid=0, gid=0, fmode=0o640, dmode=0o750):
    """Purpose: copy a directory tree, setting owner and mode on everything, and say whether anything changed.
    Inputs:  src, dst — directories; uid, gid — owner of every copied directory and file; fmode, dmode — modes.
    Returns: True when dst was created or a file was new or different (compared byte for byte), else False.
             Directories get owner and mode on every call; unchanged files are left as they are.
    Fails:   OSError from listing, copying, chown or chmod. Files in dst that are not in src are kept.
    Feeds:   deploy/* (the fabric tree, web assets, docs, service config trees, build contexts, seeds)."""
    changed = False
    if not os.path.exists(dst):
        os.makedirs(dst)
        changed = True
    os.chown(dst, uid, gid)
    os.chmod(dst, dmode)
    for item in os.listdir(src):
        s, d = os.path.join(src, item), os.path.join(dst, item)
        if os.path.isdir(s):
            changed |= copy_tree_with_perms(s, d, uid, gid, fmode, dmode)
        elif not os.path.exists(d) or not same_content(s, d):
            shutil.copy2(s, d)
            os.chown(d, uid, gid)
            os.chmod(d, fmode)
            changed = True
    return changed
