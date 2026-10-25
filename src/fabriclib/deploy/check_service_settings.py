import ipaddress
import re

from fabriclib.common.errors import ValidationError

# a container image as Docker and Podman take it: [registry[:port]/]path[:tag][@sha256:digest], lower-case path
IMAGE_RE = re.compile(r"^(?:[a-z0-9.-]+(?::[0-9]+)?/)?[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
                      r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[0-9a-f]{64})?$")
# image_* settings that are not one image
NOT_IMAGES = {"image_pins", "image_prune", "image_rolled_back", "image_signature_check"}


def check_service_settings(v):
    """Purpose: check the settings every service's container is started with, before anything is rendered: what Docker
             would otherwise refuse only at start, half-way through an apply (the owner's answer of 2026-10-12, gaps of
             2.3.1.20.2).
    Inputs:  v — rendered settings: every image_<service> (empty: not used, or pending), every ip_<service>,
             fabric_subnet. (posix_id_start and posix_id_block are retired: a DC's id range is its number's,
             2.1.6.86.)
    Returns: None.
    Fails:   ValidationError naming the setting: an image that is not an image reference; an ip_ that is not an IPv4
             address inside fabric_subnet (its network or broadcast address included), or one two services share.
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
