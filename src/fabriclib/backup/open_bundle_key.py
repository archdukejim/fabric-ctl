from fabriclib.backup.run_age import run_age
from fabriclib.common.errors import ValidationError


def open_bundle_key(sealed, passphrase=None, private_key=None):
    """Purpose: the bundle's private key out of its key.age, with the passphrase or the schedule's private key.
    Inputs:  sealed — key.age's bytes; passphrase — str, or None; private_key — "AGE-SECRET-KEY-1…" str, or None.
             Exactly one of the last two.
    Returns: the bundle's private key, str, held in memory only.
    Fails:   ValidationError when neither or both are given, for a wrong passphrase or key (age says why), or when
             key.age holds no key.
    Feeds:   open_section."""
    if (passphrase is None) == (private_key is None):
        raise ValidationError("a bundle is opened by its passphrase or its private key: give one of them")
    if private_key is not None:
        out = run_age(["-d", "-i", "{identity}"], data=sealed, identity=private_key.strip())
    else:
        out = run_age(["-d"], data=sealed, passphrase=passphrase)
    identity = out.decode(errors="replace").strip()
    if not identity.startswith("AGE-SECRET-KEY-1"):
        raise ValidationError("the bundle's key.age holds no key: the bundle is not whole")
    return identity
