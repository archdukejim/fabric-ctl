import re
import time

KINDS = ("manual", "scheduled", "uninstall", "reinstall")
SUFFIX = ".fabric.tar"
PATTERN = re.compile(r"^fabric-(?P<host>[A-Za-z0-9-]+)-(?P<when>\d{8}T\d{6}Z)-(?P<kind>[a-z]+)\.fabric\.tar$")


def bundle_name(host, kind, now=None):
    """Purpose: a bundle's file name (manual 1.3.7.2): fabric-<host>-<UTC yyyymmddThhmmssZ>-<kind>.fabric.tar.
    Inputs:  host — the host's name (a DNS label); kind — one of KINDS; now — seconds since the epoch, or None.
    Returns: str.
    Fails:   ValueError for an unknown kind or a host that is not a label.
    Feeds:   make_bundle; PATTERN is read by list_bundles and prune_bundles."""
    if kind not in KINDS:
        raise ValueError(f"unknown bundle kind {kind!r}")
    if not re.fullmatch(r"[A-Za-z0-9-]+", host or ""):
        raise ValueError(f"host name {host!r} is not a DNS label")
    return f"fabric-{host}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime(now))}-{kind}{SUFFIX}"
