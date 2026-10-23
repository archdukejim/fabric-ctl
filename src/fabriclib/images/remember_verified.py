import json
import os
import time


def remember_verified(cache, refs):
    """Purpose: record digests whose signature verified, so they are not checked again (manual 1.14.3.4): online by
             verify_signature, offline from a bundle by import_bundle.
    Inputs:  cache — str, path of the verified-digests file (root, 0600); refs — iterable of "repo:tag@sha256:…".
    Returns: dict, the file's content after the change ({digest: {"ref", "at"}}).
    Fails:   OSError if the file cannot be read or written (unreadable JSON counts as empty).
    Feeds:   images/verify_signature, images/bundle/import_bundle."""
    known = {}
    if os.path.exists(cache):
        try:
            with open(cache) as f:
                known = json.load(f)
        except ValueError:
            known = {}
    at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for ref in refs:
        known[ref.split("@", 1)[1]] = {"ref": ref, "at": at}
    os.makedirs(os.path.dirname(cache), mode=0o700, exist_ok=True)
    fd = os.open(cache, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(known, f, indent=2)
    return known
