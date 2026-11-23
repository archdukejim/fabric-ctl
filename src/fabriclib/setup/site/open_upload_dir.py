import os

from fabriclib.setup.site.close_upload_dir import close_upload_dir
from fabriclib.setup.site.constants import SITE_ID, UPLOAD_DIR


def open_upload_dir(path=UPLOAD_DIR, uid=SITE_ID, chown=None):
    """Purpose: the folder Restore from a backup's upload lands in (manual 1.3.7.10), made fresh for the bundle's
             question: the listener's (uid and gid 649), 0700, inside a root-owned parent it cannot write, so it can
             put nothing elsewhere. Whatever an earlier site left there is removed first.
    Inputs:  path — the folder; uid — the listener's uid and gid; chown — os.chown when None (tests give their own).
    Returns: path.
    Fails:   OSError.
    Feeds:   setup/site/ask_restore."""
    close_upload_dir(path)                 # first: it also removes an empty parent
    parent = os.path.dirname(path)
    os.makedirs(parent, mode=0o755, exist_ok=True)
    os.chmod(parent, 0o755)
    os.mkdir(path, 0o700)
    (chown or os.chown)(path, uid, uid)
    return path
