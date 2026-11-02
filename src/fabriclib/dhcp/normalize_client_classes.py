import ipaddress
import re

from fabriclib.common.errors import ValidationError
from fabriclib.dhcp.normalize_options import normalize_options

CLASS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
# Kea's own class names and prefixes: a fabric class may not take them
RESERVED = {"ALL", "KNOWN", "UNKNOWN", "DROP", "BOOTP", "SKIP_DDNS"}
RESERVED_PREFIXES = ("VENDOR_CLASS_", "HA_", "SPAWN_", "AFTER_")


def normalize_client_classes(classes):
    """Purpose: check dhcp.client_classes (manual 1.10.2.3): clients matched by a Kea expression get
             their own options, and for network boot their own next-server, server name and boot file.
    Inputs:  classes — list of {name, test, options, next_server, server_hostname, boot_file_name, additional
             (true: Kea's only-in-additional-list), marker (true: a class with no test that a reservation assigns)},
             or None. fabric's netboot classes use additional and marker (manual 1.10.4.25).
    Returns: the classes normalized (options through normalize_options; empty optional fields left out; a marker is
             {name, marker} alone).
    Fails:   ValidationError: not a list; a bad, reserved (ALL, KNOWN, VENDOR_CLASS_…) or repeated name; no test
             or one longer than 1000 characters or with a line break; next_server not an IPv4 address; a
             server name or boot file longer than 63 / 127 characters; errors of normalize_options. Kea checks the
             expression itself (deploy_kea).
    Feeds:   normalize_dhcp, dhcp/add_client_class."""
    if classes is None:
        return []
    if not isinstance(classes, list):
        raise ValidationError("dhcp.client_classes must be a list")
    out, seen = [], set()
    for c in classes:
        if not isinstance(c, dict):
            raise ValidationError(f"client class {c!r}: name, test and options")
        name = str(c.get("name", "")).strip()
        if not CLASS_RE.match(name) or name.upper() in RESERVED or name.upper().startswith(RESERVED_PREFIXES):
            raise ValidationError(f"client class {name!r}: letters, digits, _ . - (not one of Kea's own names)")
        if name in seen:
            raise ValidationError(f"client class {name} is defined twice")
        seen.add(name)
        if c.get("marker") is True:       # a netboot marker: no test, assigned by a reservation (2.1.10.25)
            out.append({"name": name, "marker": True})
            continue
        test = str(c.get("test", "")).strip()
        if not test or len(test) > 1000 or "\n" in test:
            raise ValidationError(f"client class {name}: a test (one Kea expression, e.g. option[93].hex == 0x0007)")
        entry = {"name": name, "test": test, "options": normalize_options(c.get("options"), f"client class {name}")}
        if c.get("additional") is True:   # evaluated only where a subnet names it (netboot, 2.1.10.25)
            entry["additional"] = True
        if c.get("next_server"):
            try:
                entry["next_server"] = str(ipaddress.IPv4Address(str(c["next_server"]).strip()))
            except ValueError:
                raise ValidationError(f"client class {name}: next_server is an IPv4 address")
        for key, limit in (("server_hostname", 63), ("boot_file_name", 127)):
            value = str(c.get(key) or "").strip()
            if len(value) > limit or "\n" in value:
                raise ValidationError(f"client class {name}: {key} is at most {limit} characters")
            if value:
                entry[key] = value
        out.append(entry)
    return out
