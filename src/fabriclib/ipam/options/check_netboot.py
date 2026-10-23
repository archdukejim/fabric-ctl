import ipaddress
import re

from fabriclib.common.errors import ValidationError

NAME_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}"
                     r"[A-Za-z0-9])?)*$")
FILE_MAX, URL_MAX = 127, 127          # the packet's file field holds 128 bytes (Kea refuses more)
FILES = ("bios", "uefi", "arm64")
URLS = ("ipxe", "http")


def _text(value, what, limit):
    """Purpose: one field of a preset: one line of printable text, at most `limit` characters.
    Inputs:  value — as given; what — its name for messages; limit — int.
    Returns: str, stripped ("" when not given).
    Fails:   ValidationError for a line break, a space or quote, or too long.
    Feeds:   check_netboot."""
    text = str(value or "").strip()
    if len(text) > limit or any(ch in text for ch in "\r\n\"' \t") or any(ord(ch) < 32 for ch in text):
        raise ValidationError(f"netboot {what}: one word of at most {limit} characters, no spaces or quotes")
    return text


def check_netboot(preset):
    """Purpose: a netboot preset checked (decision 2.1.10.25, manual 1.10.4.25): a boot server and at least one way to
             boot: PXE files by architecture, an iPXE script's URL, a UEFI HTTP boot URL.
    Inputs:  preset — {"server", "bios", "uefi", "arm64", "ipxe", "http"} (missing or "" fields left out).
    Returns: (the preset normalized, with only the fields set; list of warnings: a server given by name, which some
             firmware ignores; iPXE binaries handed out with no iPXE script, which would loop).
    Fails:   ValidationError: no server; a server that is neither an IPv4 address nor a DNS name; nothing to boot; a
             file or URL with spaces, quotes or line breaks or too long; a URL not http:// or https://.
    Feeds:   ipam/options/set_netboot."""
    server = str(preset.get("server") or "").strip().rstrip(".")
    if not server:
        raise ValidationError("netboot: give the boot server (--server: its address, or its name in DNS)")
    warnings = []
    try:
        server = str(ipaddress.IPv4Address(server))
    except ValueError:
        if not NAME_RE.match(server) or server.replace(".", "").isdigit():
            raise ValidationError(f"netboot server {server!r}: an IPv4 address or a DNS name")
        warnings.append(f"the boot server is a name ({server}): it is sent as option 66 and the server-name field; "
                        "firmware that reads only the next-server address will not find it, give an address for those")
    out = {"server": server}
    for key in FILES:
        value = _text(preset.get(key), key, FILE_MAX)
        if value:
            out[key] = value
    for key in URLS:
        value = _text(preset.get(key), key, URL_MAX)
        if value:
            if not value.lower().startswith(("http://", "https://")):
                raise ValidationError(f"netboot {key}: a URL starting http:// or https://")
            out[key] = value
    if len(out) == 1:
        raise ValidationError("netboot: nothing to boot: give --bios, --uefi or --arm64 (PXE files), --ipxe (an iPXE "
                              "script's URL) or --http (a UEFI HTTP boot URL)")
    if "ipxe" not in out and any(w in out.get(k, "").lower() for k in FILES for w in ("ipxe", "kpxe")):
        warnings.append("the PXE files look like iPXE binaries but no iPXE script is given (--ipxe): a client running "
                        "iPXE would be handed iPXE again")
    return out, warnings
