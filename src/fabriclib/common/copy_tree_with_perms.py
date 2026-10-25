import os
import shutil


def _same_content(a, b):
    """Purpose: say whether two files hold the same bytes, reading both every time. `filecmp.cmp` caches its answer
             by each file's (type, size, mtime) even with shallow=False, so a same-size rewrite within one mtime
             tick read as unchanged and was never copied (2.3.10.11.19).
    Inputs:  a, b — paths of two regular files.
    Returns: True when sizes and every byte match, else False.
    Fails:   OSError from stat or read.
    Feeds:   copy_tree_with_perms."""
    if os.path.getsize(a) != os.path.getsize(b):
        return False
    with open(a, "rb") as fa, open(b, "rb") as fb:
        while True:
            ca, cb = fa.read(65536), fb.read(65536)
            if ca != cb:
                return False
            if not ca:
                return True


def copy_tree_with_perms(src, dst, uid=0, gid=0, fmode=0o640, dmode=0o750):
    """Purpose: copy a directory tree, setting owner and mode on everything, and say whether anything changed.
    Inputs:  src, dst — directories; uid, gid — owner of every copied directory and file; fmode, dmode — modes.
    Returns: True when dst was created or a file was new or different (compared byte for byte), else False.
             Directories get owner and mode on every call; unchanged files are left as they are. Python's bytecode
             caches (`__pycache__`, `*.pyc`) are never copied: a host process importing fabric's code writes them
             into the source, and copied into the web console's build context they counted as a change, rebuilding
             its image and restarting it (the console gone ~25 s) at the next apply (2.3.10.11.16).
    Fails:   OSError from listing, copying, chown or chmod. Files in dst that are not in src are kept.
    Feeds:   deploy/* (the fabric tree, web assets, docs, service config trees, build contexts, seeds)."""
    changed = False
    if not os.path.exists(dst):
        os.makedirs(dst)
        changed = True
    os.chown(dst, uid, gid)
    os.chmod(dst, dmode)
    for item in os.listdir(src):
        if item == "__pycache__" or item.endswith(".pyc"):
            continue
        s, d = os.path.join(src, item), os.path.join(dst, item)
        if os.path.isdir(s):
            changed |= copy_tree_with_perms(s, d, uid, gid, fmode, dmode)
        elif not os.path.exists(d) or not _same_content(s, d):
            shutil.copy2(s, d)
            os.chown(d, uid, gid)
            os.chmod(d, fmode)
            changed = True
    return changed
