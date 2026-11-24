from fabriclib.backup.run_age import run_age
from fabriclib.common.errors import ValidationError


def seal_bundle_key(identity, passphrase=None, public_key=None):
    """Purpose: the bundle's private key, encrypted with a passphrase (a bundle made by hand, at uninstall or at
             reinstall) or to the schedule's public key (a scheduled bundle), as the bundle's key.age (manual 1.3.7.2).
    Inputs:  identity — the bundle's private key; passphrase — str, or None; public_key — "age1…" str, or None.
             Exactly one of the last two.
    Returns: key.age's content, ASCII-armored bytes.
    Fails:   ValidationError when neither or both are given, for a public key that is not age1…, or from run_age.
    Feeds:   make_bundle."""
    if (passphrase is None) == (public_key is None):
        raise ValidationError("a bundle is opened by a passphrase or a public key: give one of them")
    if public_key is not None:
        if not public_key.startswith("age1") or not public_key.isalnum():
            raise ValidationError("the public key is not an age public key (age1…)")
        return run_age(["-a", "-r", public_key], data=identity.encode() + b"\n")
    return run_age(["-a", "-p"], data=identity.encode() + b"\n", passphrase=passphrase)
