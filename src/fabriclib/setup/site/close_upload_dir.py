import os
import shutil


def close_upload_dir(path):
    """Purpose: the upload folder gone with whatever is in it (manual 1.3.7.10): once the bundle is picked, or the
             restore stopped, nothing the listener could write is left, and an upload never stays half-sent.
    Inputs:  path — the folder (setup/site/constants.UPLOAD_DIR).
    Returns: None.
    Fails:   OSError other than its absence.
    Feeds:   open_upload_dir, ask_restore."""
    if os.path.islink(path):
        os.remove(path)
    elif os.path.isdir(path):
        shutil.rmtree(path)
    parent = os.path.dirname(path)
    if os.path.isdir(parent) and not os.listdir(parent):
        os.rmdir(parent)
