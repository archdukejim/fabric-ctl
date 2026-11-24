import subprocess

from fabriclib.common.errors import ValidationError


def make_bundle_key():
    """Purpose: a new age key pair for one bundle (decision 2.1.3.6): every section is encrypted to its public half,
             and only the private half is sealed with the passphrase or the schedule's public key (seal_bundle_key),
             so age's passphrase prompt runs once per bundle, on a few bytes.
    Inputs:  none.
    Returns: (identity, recipient): the private key "AGE-SECRET-KEY-1…" and its public key "age1…", both str, held
             in memory only (age-keygen writes to its stdout, never a file).
    Fails:   ValidationError when age-keygen fails or prints no key; OSError when it is not installed.
    Feeds:   make_bundle."""
    res = subprocess.run(["age-keygen"], capture_output=True, text=True)
    if res.returncode != 0:
        raise ValidationError(f"age-keygen failed: {res.stderr.strip()[:200]}")
    identity = next((line for line in res.stdout.splitlines() if line.startswith("AGE-SECRET-KEY-1")), None)
    recipient = next((line.split(":", 1)[1].strip() for line in res.stdout.splitlines()
                      if line.startswith("# public key:")), None)
    if not identity or not recipient:
        raise ValidationError("age-keygen printed no key")
    return identity, recipient
