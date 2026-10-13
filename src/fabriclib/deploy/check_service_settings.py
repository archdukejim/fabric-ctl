import ipaddress
import re

from fabriclib.common.errors import ValidationError

# a container image as Docker and Podman take it: [registry[:port]/]path[:tag][@sha256:digest], lower-case path
IMAGE_RE = re.compile(r"^(?:[a-z0-9.-]+(?::[0-9]+)?/)?[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
                      r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[0-9a-f]{64})?$")
# image_* settings that are not one image
NOT_IMAGES = {"image_pins", "image_prune", "image_rolled_back", "image_signature_check"}
ID_MAX = 2 ** 31 - 1                    # the largest uid/gid Linux and AD both take
BLOCK = 1_000_000                       # a site's id block: a million ids from a multiple of a million (2.1.6.46)


def _whole(v, key, low):
    """Purpose: one setting as a whole number, at least low.
    Inputs:  v — settings; key — the setting's name; low — the smallest value taken.
    Returns: int.
    Fails:   ValidationError naming the setting, for anything else.
    Feeds:   check_service_settings."""
    text = str(v.get(key, "")).strip()
    if not text.isdigit() or int(text) < low:
        raise ValidationError(f"{key} must be a whole number, at least {low} (got {text!r})")
    return int(text)


def check_service_settings(v):
    """Purpose: check the settings every service's container is started with, before anything is rendered: what Docker
             would otherwise refuse only at start, half-way through an apply (the owner's answer of 2026-10-12, gaps of
             2.3.1.20.2).
    Inputs:  v — rendered settings: every image_<service> (empty: not used, or pending), every ip_<service>,
             fabric_subnet, posix_id_start and posix_id_block.
    Returns: None.
    Fails:   ValidationError naming the setting: an image that is not an image reference; an ip_ that is not an IPv4
             address inside fabric_subnet (its network or broadcast address included), or one two services share;
             posix_id_start under 1000 (the system's own ids) or posix_id_block under 1000, or a first block that
             does not fit under 2^31 - 1; a posix_id_start that is not a multiple of 1000000 or a posix_id_block other
             than 1000000 (a site's block, whose fixed ranges the DC hands ids from, 2.1.6.46; the one-run block of an
             install from before 0.7.0 is no longer served, 2.1.6.51, S11).
    Feeds:   deploy/check_settings."""
    for key in sorted(k for k in v if k.startswith("image_") and k not in NOT_IMAGES):
        ref = v.get(key)
        if ref in (None, ""):
            continue
        if not isinstance(ref, str) or not IMAGE_RE.match(ref):
            raise ValidationError(f"{key} is not a container image (registry/name:tag or @sha256:digest; got {ref!r})")
    try:
        net = ipaddress.IPv4Network(str(v.get("fabric_subnet") or "10.255.0.0/24"), strict=False)
    except ValueError:
        raise ValidationError(f"fabric_subnet is not an IPv4 network (got {v.get('fabric_subnet')!r})") from None
    taken = {}
    for key in sorted(k for k in v if k.startswith("ip_")):
        if v.get(key) in (None, ""):
            continue
        try:
            ip = ipaddress.IPv4Address(str(v[key]))
        except ValueError:
            raise ValidationError(f"{key} is not an IPv4 address (got {v[key]!r})") from None
        if ip not in net or ip in (net.network_address, net.broadcast_address):
            raise ValidationError(f"{key} {ip} is not a host address in fabric's network, fabric_subnet {net}")
        if ip in taken:
            raise ValidationError(f"{key} {ip} is already {taken[ip]}'s address: each service needs its own")
        taken[ip] = key
    start = _whole(v, "posix_id_start", 1000) if "posix_id_start" in v else None
    block = _whole(v, "posix_id_block", 1000) if "posix_id_block" in v else None
    if start is not None and start + (block or 0) - 1 > ID_MAX:
        raise ValidationError(f"posix_id_start {start} with posix_id_block {block} goes past {ID_MAX}, the largest "
                              "uid and gid Linux and AD take")
    if start is not None and start % BLOCK:
        raise ValidationError(f"posix_id_start must be a multiple of {BLOCK} (got {start}): a site's id block starts "
                              "there (2.1.6.46)")
    if block is not None and block != BLOCK:
        raise ValidationError(f"posix_id_block must be {BLOCK} (got {block}): every site's id block is a million long "
                              "(2.1.6.46)")
