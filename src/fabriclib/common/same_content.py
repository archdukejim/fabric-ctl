import os


def same_content(a, b):
    """Purpose: say whether two files hold the same bytes, reading both every time. `filecmp.cmp` caches its answer
             by each file's (type, size, mtime) even with shallow=False, so a same-size rewrite within one mtime
             tick read as unchanged and was never copied (2.3.1.29; found on dev/0.9.0, 2.3.10.11.19).
    Inputs:  a, b — paths of two regular files.
    Returns: True when sizes and every byte match, else False.
    Fails:   OSError from stat or read.
    Feeds:   common/copy_tree_with_perms, common/copy_if_changed, federation/deploy_federation_endpoint,
             pki/publish_ca_certs."""
    if os.path.getsize(a) != os.path.getsize(b):
        return False
    with open(a, "rb") as fa, open(b, "rb") as fb:
        while True:
            ca, cb = fa.read(65536), fb.read(65536)
            if ca != cb:
                return False
            if not ca:
                return True
