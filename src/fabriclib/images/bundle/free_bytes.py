import os


def free_bytes(path):
    """Purpose: the space free for fabric on the filesystem holding `path` (its nearest existing folder).
    Inputs:  path — str, a file or folder that may not exist yet.
    Returns: int bytes available to root's processes there (statvfs f_bavail × f_frsize).
    Fails:   OSError when no part of the path can be examined.
    Feeds:   export_bundle, import_bundle."""
    probe = os.path.abspath(path)
    while not os.path.exists(probe):
        probe = os.path.dirname(probe)
    st = os.statvfs(probe)
    return st.f_bavail * st.f_frsize
