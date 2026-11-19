import tarfile

from fabriclib.backup.open_bundle_key import open_bundle_key


def bundle_key_from(path, passphrase=None, private_key=None):
    """Purpose: a bundle's own private key, opened from its key.age with the passphrase or the private key.
    Inputs:  path — a bundle; passphrase / private_key — exactly one.
    Returns: the bundle's private key, str.
    Fails:   ValidationError from open_bundle_key (a wrong passphrase or key).
    Feeds:   restore_bundle, restore_section."""
    with tarfile.open(path, mode="r:") as outer:
        sealed = outer.extractfile("key.age").read()
    return open_bundle_key(sealed, passphrase=passphrase, private_key=private_key)
